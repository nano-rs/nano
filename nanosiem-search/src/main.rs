// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Search Service binary
//!
//! Requirements: 1.3, 3.1, 3.2, 3.3

use anyhow::Result;
use nanosiem_core::auth::{
    repository::ApiKeyRepository, ApiKeyService, PermissionResolver, SourceScopeResolver,
    TokenConfig, TokenService,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::auth::TenantMembershipResolver;
use nanosiem_core::db::repository::RateLimitRepository;
use nanosiem_core::db::ClickHouseMigrator;
use nanosiem_core::leader::lock_ids;
#[cfg(feature = "enterprise")]
use nanosiem_core::tenant_entitlements::TenantEntitlementResolver;
use nanosiem_core::{DualPool, DualPoolConfig, LeaderElection};
use std::net::SocketAddr;

use nanosiem_search::{create_router, AuthState, SearchConfig, SearchMetrics, SearchState};

const ALLOCATOR_TRIM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const ALLOCATOR_TRIM_MINIMUM_RSS_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(feature = "enterprise")]
fn enterprise_shared_routes_closed(deployment_mode: Option<&str>) -> Result<bool> {
    match deployment_mode {
        Some("enterprise_shared") => Ok(true),
        None | Some("") | Some("managed") | Some("selfhosted") | Some("self-hosted")
        | Some("demo") => Ok(false),
        Some(value) => Err(anyhow::anyhow!(
            "invalid DEPLOYMENT_MODE {value:?} for search service"
        )),
    }
}

/// Open builds cannot serve the hosted shared profile: refuse it at boot,
/// before any database or listener is touched. Dedicated profiles parse as
/// in the enterprise build; unknown values still fail closed.
#[cfg(not(feature = "enterprise"))]
fn open_deployment_mode(deployment_mode: Option<&str>) -> Result<bool> {
    match deployment_mode {
        Some("enterprise_shared") => Err(anyhow::anyhow!(
            "enterprise_shared Search requires the enterprise feature"
        )),
        None | Some("") | Some("managed") | Some("selfhosted") | Some("self-hosted")
        | Some("demo") => Ok(false),
        Some(value) => Err(anyhow::anyhow!(
            "invalid DEPLOYMENT_MODE {value:?} for search service"
        )),
    }
}

/// NAN-3286: an enterprise-shared search process serves tenants only from
/// tenant-pinned lake views. On the ClickHouse backend its process singleton
/// would hold a broad, tenant-unpredicated client, so refuse to boot rather
/// than rely on every handler avoiding it.
fn require_shared_lake_backend(shared_profile: bool, canonical_lake: bool) -> Result<()> {
    if shared_profile && !canonical_lake {
        return Err(anyhow::anyhow!(
            "DEPLOYMENT_MODE=enterprise_shared requires NANO_LOG_QUERY_BACKEND=lake; \
             refusing search startup on a non-lake backend"
        ));
    }
    Ok(())
}

/// Capabilities this binary reports to `--print-features` (NAN-3531 N2a).
/// `hosted_config_dir_v1`: hosted producer configs reload live from
/// `NANO_SHARED_HOSTED_JOB_CONFIG_DIR`, and `/internal/hosted-config` reports
/// the loaded revision. Only the enterprise build carries the reload.
#[cfg(feature = "enterprise")]
const APP_FEATURES: &[&str] = &[nanosiem_core::search::hosted_producer_reload::HOSTED_CONFIG_DIR_FEATURE];
#[cfg(not(feature = "enterprise"))]
const APP_FEATURES: &[&str] = &[];

#[tokio::main]
async fn main() -> Result<()> {
    if nanosiem_core::app_features::print_if_requested(APP_FEATURES) {
        return Ok(());
    }
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-search");

    tracing::info!("Starting NanoSIEM Search Service");

    // Load configuration from environment
    let config = SearchConfig::from_env();
    #[cfg(feature = "enterprise")]
    let shared_profile =
        enterprise_shared_routes_closed(std::env::var("DEPLOYMENT_MODE").ok().as_deref())?;
    #[cfg(not(feature = "enterprise"))]
    let shared_profile = open_deployment_mode(std::env::var("DEPLOYMENT_MODE").ok().as_deref())?;
    tracing::info!("Configuration loaded: port={}", config.port);

    // Initialize DualPool (ClickHouse + PostgreSQL)
    tracing::info!("Connecting to databases...");
    let mut dual_pool_config = DualPoolConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to load database config: {}", e))?;
    dual_pool_config.pg_max_connections = dual_pool_config.pg_max_connections.max(2);
    dual_pool_config.pg_min_connections = dual_pool_config.pg_min_connections.max(2);
    // The authority statement itself detects a dead socket and fails closed;
    // avoid an extra ping round trip on every pooled request by default.
    if std::env::var_os("PG_TEST_BEFORE_ACQUIRE").is_none() {
        dual_pool_config.pg_test_before_acquire = false;
    }

    // NAN-3491: one central resolution; unset selects the lake and a legacy
    // `clickhouse`/`shadow`/`udm` value refuses to boot.
    let runtime = nanosiem_core::schema::runtime_profile_from_env()
        .map_err(|error| anyhow::anyhow!("Refusing to start: {error}"))?;
    let canonical_lake = runtime.backend == nanosiem_core::schema::LogQueryBackend::Lake;
    require_shared_lake_backend(shared_profile, canonical_lake)?;
    let mut dual_pool = DualPool::new_lake_control_plane_with_min_connections(&dual_pool_config, 2)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to lake control plane: {}", e))?;
    // NAN-3231: say what the admission pool really does. On the lake control
    // plane an opted-in ping runs as a counted `before_acquire` round trip.
    tracing::info!(
        pg_max_connections = dual_pool.postgres().options().get_max_connections(),
        pg_test_before_acquire = dual_pool_config.pg_test_before_acquire,
        canonical_lake,
        "search PostgreSQL admission pool configured"
    );

    // Search is a direct enterprise-shared data-plane ingress. It must attest
    // the exact live RLS catalog itself before spawning refreshers, building a
    // router, or binding a listener; API process health is not a transitive
    // authorization guarantee for this independently deployed service.
    if shared_profile {
        let runtime_role = std::env::var("NANOSIEM_SHARED_RLS_RUNTIME_ROLE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "NANOSIEM_SHARED_RLS_RUNTIME_ROLE is required in enterprise_shared mode"
                )
            })?;
        let owner_role = std::env::var("NANOSIEM_SHARED_RLS_OWNER_ROLE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "NANOSIEM_SHARED_RLS_OWNER_ROLE is required in enterprise_shared mode"
                )
            })?;
        nanosiem_core::tenant_db::require_tenant_rls_catalog(
            dual_pool.postgres(),
            &runtime_role,
            &owner_role,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "enterprise-shared RLS catalog verification failed; refusing search startup: {error}"
            )
        })?;
        tracing::info!("Enterprise-shared search RLS catalog verification is green");
    }

    // NAN-2361: on a lake backend, resolve the field inventory from the QUERY
    // WORKER rather than a manifest copied out of the generation volume.
    //
    // An external search process cannot read that volume, and nothing publishes
    // a fresh copy when generations rotate, so a copy taken at setup silently
    // freezes: every field promoted afterwards reads as "Unknown canonical OCSF
    // field" no matter what the lake holds. That failure blames the query rather
    // than the schema, which is what makes it expensive to diagnose.
    //
    // Startup failure is NOT fatal -- the file path remains as a fallback, and
    // refusing to boot because the worker is briefly unreachable would turn a
    // schema-freshness problem into an outage.
    // NAN-2718: a shared Search serves many tenants. A process-global schema
    // URL names ONE tenant's worker; refuse to start rather than show that
    // tenant's field inventory to every tenant. Each tenant's schema is loaded
    // from its own registry-assigned worker and cached by tenant UUID.
    if shared_profile {
        nanosiem_core::schema::worker_schema::refuse_global_schema_in_shared_mode(&|name: &str| {
            std::env::var(name).ok()
        })
        .map_err(|error| anyhow::anyhow!("Refusing to start: {error}"))?;
        if canonical_lake {
            nanosiem_core::schema::tenant_lake_schema::start_for_shared_process().await;
        }
    } else if canonical_lake {
        match nanosiem_core::schema::worker_schema::WorkerSchemaSource::from_env() {
            Ok(Some(source)) => {
                match source.refresh().await {
                    Ok(_) => tracing::info!("installed lake schema from the query worker"),
                    Err(error) => tracing::warn!(
                        %error,
                        "could not fetch the lake schema from the query worker; \
                         falling back to the configured manifest, which may be stale"
                    ),
                }
                // The field SET changes far less often than generations rotate,
                // and the response carries a digest, so an unchanged schema
                // short-circuits before any profile is rebuilt. This keeps a
                // long-running search current without a restart.
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        match source.refresh().await {
                            Ok(true) => tracing::info!("lake schema changed; profile rebuilt"),
                            Ok(false) => {}
                            Err(error) => tracing::warn!(
                                %error,
                                "lake schema refresh failed; keeping the installed schema"
                            ),
                        }
                    }
                });
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                %error,
                "lake schema source is misconfigured; falling back to the configured manifest"
            ),
        }
    }

    // Verify ClickHouse schema is up-to-date. The pre-deploy migrator
    // (NAN-607) is responsible for applying migrations — this is the
    // safety net that refuses to serve queries against a stale schema
    // (e.g., a deploy that bypassed the K8s pre-deploy Job or compose
    // `clickhouse-migrate` service).
    if !canonical_lake {
        let (admin_client, _) = dual_pool_config.create_admin_clickhouse_client();
        let migrator =
            ClickHouseMigrator::new(admin_client, dual_pool_config.clickhouse_database.clone());
        let migrations_path = std::path::Path::new("./clickhouse");
        migrator
            .check_schema_up_to_date(migrations_path)
            .await
            .map_err(|e| anyhow::anyhow!("Refusing to start: {}", e))?;
        tracing::info!("ClickHouse schema version OK");
    }

    // Re-detect cluster state — DualPool::new() may have run before the init-db job
    // created distributed tables. The init container waits for the DB to exist, so
    // by now logs_distributed should be present in clustered deployments.
    if !canonical_lake {
        dual_pool
            .refresh_cluster_state(&dual_pool_config.clickhouse_database)
            .await;
    } else {
        tracing::info!(
            "Skipping ClickHouse migrations and cluster detection in canonical lake mode"
        );
    }

    tracing::info!("Database connections established");

    // Initialize auth services
    let auth_enabled = std::env::var("AUTH_ENABLED")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    let auth_state = if auth_enabled {
        tracing::info!("Authentication enabled");

        // Create token service
        let token_config = TokenConfig::default();
        let token_service = TokenService::new(token_config);

        // NAN-682: wire the shared Dragonfly-backed JTI denylist so logout-driven
        // revocations issued on any API replica are visible to every search pod
        // before the access token's natural 15-min expiry. Falls back to a
        // per-pod denylist (current behaviour, blind to API revocations) when
        // REDIS_URL is unset — acceptable for single-node dev/test only.
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            if !redis_url.is_empty() {
                match nanosiem_core::auth::token::redis_denylist_from_url(&redis_url).await {
                    Ok(denylist) => {
                        token_service.set_redis(denylist);
                        tracing::info!("JWT JTI denylist initialized with Redis (cross-pod revocation enabled)");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to initialize Redis JTI denylist; falling back to per-pod denylist")
                    }
                }
            }
        } else {
            tracing::info!("REDIS_URL not set — JWT JTI denylist is per-pod (cross-pod logout revocation disabled)");
        }

        // Create API key service for validating X-API-Key headers
        let api_key_repo = ApiKeyRepository::new(dual_pool.postgres().clone());
        let rate_limit_repo = RateLimitRepository::new(dual_pool.postgres().clone());
        let api_key_service = ApiKeyService::new(api_key_repo, rate_limit_repo);

        let permission_resolver = PermissionResolver::new(dual_pool.postgres().clone());
        // NAN-1797: fail-closed per-user source-scope resolver. Shares the same
        // PG pool as the permission resolver; the search AuthContext carries the
        // resolved deny set so every logs-touching handler can scope its query.
        let source_scope_resolver = SourceScopeResolver::new(dual_pool.postgres().clone());
        // F-32: fail-closed per-user status/revocation gate for the JWT path.
        let user_status_resolver =
            nanosiem_core::auth::UserStatusResolver::new(dual_pool.postgres().clone());
        AuthState::new(token_service, Some(api_key_service), true)
            .with_permission_resolver(permission_resolver)
            .with_source_scope_resolver(source_scope_resolver)
            .with_user_status_resolver(user_status_resolver)
    } else {
        tracing::warn!("Authentication DISABLED - all requests will be allowed");
        AuthState::disabled()
    };

    #[cfg(feature = "enterprise")]
    let auth_state = if shared_profile {
        let shared = auth_state
            .with_enterprise_shared_tenant_resolver(TenantMembershipResolver::new(
                dual_pool.postgres().clone(),
            ))
            .with_shared_search_entitlement_resolver(TenantEntitlementResolver::new(
                dual_pool.postgres().clone(),
            ))
            .with_shared_query_retention_pool(dual_pool.postgres().clone())
            .with_shared_session_revocation_pool(dual_pool.postgres().clone())
            .with_enterprise_shared_routes_closed(true);
        #[cfg(feature = "enterprise")]
        let shared = shared.with_shared_automation_key_service(
            nanosiem_core::enterprise_shared_automation_keys::TenantAutomationKeyService::new(
                dual_pool.postgres().clone(),
            ),
        );
        #[cfg(not(feature = "enterprise"))]
        anyhow::bail!("enterprise_shared Search requires the enterprise feature");
        shared
    } else {
        auth_state.with_enterprise_shared_routes_closed(false)
    };
    let mut state = SearchState::new(dual_pool.clone(), auth_state).await;

    // NAN-1582: when lookup row data lives in ClickHouse (the default), don't
    // serve `| lookup` / `inputlookup` / `ioc in lookup()` reads until the
    // one-time PG→CH backfill has finished — otherwise we'd read a partially
    // migrated `lookup_rows`. The search service never RUNS the backfill (single
    // runner via the PG sentinel, owned by the api/jobs pod); it only WAITS for
    // the claim to be released. Bounded so a stuck claim can't hang boot forever.
    if matches!(
        nanosiem_core::lookup::LookupStorageBackend::from_env(),
        nanosiem_core::lookup::LookupStorageBackend::ClickHouse
    ) && nanosiem_core::lookup::is_backfill_in_progress(dual_pool.postgres()).await
    {
        const BACKFILL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
        const BACKFILL_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
        tracing::info!(
            "Lookup backfill in progress — waiting up to {}s before serving CH lookup reads...",
            BACKFILL_WAIT_TIMEOUT.as_secs()
        );
        let deadline = std::time::Instant::now() + BACKFILL_WAIT_TIMEOUT;
        loop {
            tokio::time::sleep(BACKFILL_POLL_INTERVAL).await;
            if !nanosiem_core::lookup::is_backfill_in_progress(dual_pool.postgres()).await {
                tracing::info!("Lookup backfill complete; proceeding to serve.");
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "Lookup backfill did not complete within {}s; refusing to serve stale ClickHouse lookup data",
                    BACKFILL_WAIT_TIMEOUT.as_secs()
                ));
            }
            tracing::info!("Still waiting for lookup backfill to complete...");
        }
    }

    // Leader election for active/standby (gates readiness probe)
    // Default to false (active/active mode). Set to true for legacy active/standby.
    let leader_election_enabled = std::env::var("SEARCH_LEADER_ELECTION_ENABLED")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(false);
    let election_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let mut election_handle = None;

    if leader_election_enabled {
        tracing::info!("Search leader election enabled — starting advisory lock election");
        let election = LeaderElection::new(dual_pool.postgres().clone(), lock_ids::SEARCH_ACTIVE);
        let (rx, handle) = election.start(election_shutdown.clone());
        state.set_leader_rx(rx);
        election_handle = Some(handle);
    } else {
        tracing::warn!("Search leader election disabled (SEARCH_LEADER_ELECTION_ENABLED=false) — always serving traffic");
    }

    // Initialize metrics
    let (search_metrics, prometheus_layer) = SearchMetrics::new();

    // Create router
    let app = create_router(state, search_metrics, prometheus_layer, &config);

    // Start server with ConnectInfo support for capturing client IP addresses
    let bind_address = format!("0.0.0.0:{}", config.port);
    tracing::info!("Starting server on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let allocator_trim_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let allocator_trim_handle =
        tokio::spawn(nanosiem_core::allocator_trim::run_allocator_trim_loop(
            "nanosiem-search",
            ALLOCATOR_TRIM_INTERVAL,
            ALLOCATOR_TRIM_MINIMUM_RSS_BYTES,
            allocator_trim_shutdown.clone(),
        ));
    let wait_for_shutdown = async {
        match nanosiem_core::shutdown::wait_for_shutdown_signal().await {
            Ok(signal) => tracing::info!(%signal, "Shutdown signal received"),
            Err(error) => tracing::error!(%error, "Shutdown signal handler failed"),
        }
    };
    let server_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let graceful_shutdown = server_shutdown.clone();
    let server = axum::serve(listener, make_service).with_graceful_shutdown(async move {
        graceful_shutdown.cancelled().await;
    });
    let cleanup = async move {
        election_shutdown.cancel();
        allocator_trim_shutdown.cancel();
        if let Some(handle) = election_handle {
            match handle.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => tracing::warn!(?error, "Search leader election task failed"),
            }
        }
        match allocator_trim_handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::warn!(?error, "Search allocator trim task failed"),
        }
    };
    nanosiem_core::shutdown::run_server_with_shutdown(
        server,
        server_shutdown,
        wait_for_shutdown,
        cleanup,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_shared_lake_backend;
    #[cfg(feature = "enterprise")]
    use super::enterprise_shared_routes_closed;

    #[test]
    fn shared_mode_refuses_a_non_lake_backend() {
        assert!(require_shared_lake_backend(true, true).is_ok());
        assert!(require_shared_lake_backend(true, false).is_err());
        assert!(require_shared_lake_backend(false, false).is_ok());
        assert!(require_shared_lake_backend(false, true).is_ok());
    }

    /// NAN-3491: unset and the hosted `ocsf`+`lake` pair resolve to the lake,
    /// so the shared-profile guard holds for both; legacy values never boot.
    #[test]
    fn resolved_runtime_profile_satisfies_the_shared_lake_guard() {
        use nanosiem_core::schema::runtime_profile::resolve_runtime_profile;
        use nanosiem_core::schema::LogQueryBackend;
        for (schema, backend) in [(None, None), (Some("ocsf"), Some("lake"))] {
            let runtime = resolve_runtime_profile(schema, backend).unwrap();
            let canonical_lake = runtime.backend == LogQueryBackend::Lake;
            assert!(require_shared_lake_backend(true, canonical_lake).is_ok());
        }
        for backend in ["clickhouse", "shadow"] {
            assert!(resolve_runtime_profile(None, Some(backend)).is_err());
        }
    }

    #[cfg(not(feature = "enterprise"))]
    #[test]
    fn open_build_refuses_the_shared_profile_and_unknown_profiles() {
        assert!(super::open_deployment_mode(Some("enterprise_shared")).is_err());
        for dedicated in [None, Some(""), Some("managed"), Some("selfhosted"), Some("demo")] {
            assert!(!super::open_deployment_mode(dedicated).unwrap());
        }
        assert!(super::open_deployment_mode(Some("shared")).is_err());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_profile_closes_search_and_unknown_profiles_fail_closed() {
        assert!(enterprise_shared_routes_closed(Some("enterprise_shared")).unwrap());
        for dedicated in [
            None,
            Some(""),
            Some("managed"),
            Some("selfhosted"),
            Some("demo"),
        ] {
            assert!(!enterprise_shared_routes_closed(dedicated).unwrap());
        }
        assert!(enterprise_shared_routes_closed(Some("shared")).is_err());
    }
}
