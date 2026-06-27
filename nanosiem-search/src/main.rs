// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Search Service binary
//!
//! Requirements: 1.3, 3.1, 3.2, 3.3

use anyhow::Result;
use nanosiem_core::auth::{
    repository::{ApiKeyRepository, AuditRepository},
    ApiKeyService, PermissionResolver, TokenConfig, TokenService,
};
use nanosiem_core::db::repository::RateLimitRepository;
use nanosiem_core::db::ClickHouseMigrator;
use nanosiem_core::leader::lock_ids;
use nanosiem_core::{DualPool, DualPoolConfig, LeaderElection};
use std::net::SocketAddr;

use nanosiem_search::{create_router, AuthState, SearchConfig, SearchMetrics, SearchState};

#[tokio::main]
async fn main() -> Result<()> {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-search");

    tracing::info!("Starting NanoSIEM Search Service");

    // Load configuration from environment
    let config = SearchConfig::from_env();
    tracing::info!("Configuration loaded: port={}", config.port);

    // Initialize DualPool (ClickHouse + PostgreSQL)
    tracing::info!("Connecting to databases...");
    let dual_pool_config = DualPoolConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to load database config: {}", e))?;

    let mut dual_pool = DualPool::new(&dual_pool_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to databases: {}", e))?;

    // Verify ClickHouse schema is up-to-date. The pre-deploy migrator
    // (NAN-607) is responsible for applying migrations — this is the
    // safety net that refuses to serve queries against a stale schema
    // (e.g., a deploy that bypassed the K8s pre-deploy Job or compose
    // `clickhouse-migrate` service).
    {
        let (admin_client, _) = dual_pool_config.create_admin_clickhouse_client();
        let migrator = ClickHouseMigrator::new(
            admin_client,
            dual_pool_config.clickhouse_database.clone(),
        );
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
    dual_pool
        .refresh_cluster_state(&dual_pool_config.clickhouse_database)
        .await;

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
                    Err(e) => tracing::warn!(error = %e, "failed to initialize Redis JTI denylist; falling back to per-pod denylist"),
                }
            }
        } else {
            tracing::info!("REDIS_URL not set — JWT JTI denylist is per-pod (cross-pod logout revocation disabled)");
        }

        // Create API key service for validating X-API-Key headers
        let api_key_repo = ApiKeyRepository::new(dual_pool.postgres().clone());
        let audit_repo = AuditRepository::new(dual_pool.postgres().clone());
        let rate_limit_repo = RateLimitRepository::new(dual_pool.postgres().clone());
        let api_key_service = ApiKeyService::new(api_key_repo, audit_repo, rate_limit_repo);

        let permission_resolver = PermissionResolver::new(dual_pool.postgres().clone());
        AuthState::new(token_service, Some(api_key_service), true)
            .with_permission_resolver(permission_resolver)
    } else {
        tracing::warn!("Authentication DISABLED - all requests will be allowed");
        AuthState::disabled()
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

    if leader_election_enabled {
        tracing::info!("Search leader election enabled — starting advisory lock election");
        let election = LeaderElection::new(dual_pool.postgres().clone(), lock_ids::SEARCH_ACTIVE);
        let rx = election.start();
        state.set_leader_rx(rx);
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
    axum::serve(listener, make_service).await?;

    Ok(())
}
