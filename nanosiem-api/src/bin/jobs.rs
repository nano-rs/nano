// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Background Jobs Service
//!
//! Runs all background tasks (detection scheduling, signal processing,
//! enrichment sync, tuning, cleanup, etc.) separately from the HTTP API.
//! This enables independent deploy cycles, resource isolation, and
//! cleaner failure domains.

use anyhow::Result;
use nanosiem_api::{ApiConfig, AppMetrics, AppState};
use nanosiem_core::leader::lock_ids;
use nanosiem_core::license::checker::LicenseCheckerConfig;
use nanosiem_core::{Database, LeaderElection, LicenseChecker};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-jobs");

    tracing::info!("Starting NanoSIEM Jobs Service");

    // Load configuration (reuses API config — same env vars)
    let config = ApiConfig::from_env();
    tracing::info!("Configuration loaded");

    // Initialize AppState (DualPool or PG-only). SchemaBehind is a hard
    // failure — refuse to start rather than degrading silently. (NAN-607)
    let mut state = match AppState::try_with_dual_pool(config.clone()).await {
        Ok(state) => {
            tracing::info!("DualPool mode enabled - using ClickHouse for log storage");
            state
        }
        Err(nanosiem_core::db::DualPoolError::SchemaBehind(msg)) => {
            tracing::error!("Refusing to start: {}", msg);
            return Err(anyhow::anyhow!("{}", msg));
        }
        Err(e) => {
            tracing::info!(
                "DualPool not available ({}), falling back to PostgreSQL-only mode",
                e
            );
            let db = Database::connect(&config.database_url).await?;
            let pg_pool: &sqlx::PgPool = db.pool();
            // Open-tier migrations via the shared helper (handles fresh-init
            // detection + snapshot + backfill per NAN-749).
            nanosiem_core::db::run_postgres_migrations(pg_pool).await?;
            #[cfg(feature = "enterprise")]
            {
                let mut overlay_migrator =
                    sqlx::migrate!("../migrations/postgres-enterprise");
                overlay_migrator.set_ignore_missing(true);
                overlay_migrator.run(pg_pool).await?;
            }
            AppState::from_database(&db, config.clone())
        }
    };

    // Initialize demo service if DEPLOYMENT_MODE=demo
    if let Err(e) = state.init_demo_if_enabled().await {
        tracing::warn!(
            "Failed to initialize demo service: {}. Demo mode disabled.",
            e
        );
    }

    // Initialize meloD AI service (needed for tuning orchestrator). Open
    // builds skip AI init entirely — the open tuning scheduler runs without
    // proposal generation.
    #[cfg(feature = "enterprise")]
    match state.reload_melod_service().await {
        Ok(true) => tracing::info!("meloD AI service initialized"),
        Ok(false) => tracing::info!("meloD AI service not configured"),
        Err(e) => tracing::warn!("Failed to initialize meloD AI service: {}", e),
    }

    // Initialize real-time evaluator (needed for rule change listener)
    if let Err(e) = state.init_realtime_evaluator().await {
        tracing::warn!("Failed to initialize real-time evaluator: {}", e);
    }

    // === License enforcement (24h check) ===
    if state.config.is_license_enabled() {
        let license_url = state.config.license_url.clone().unwrap();
        let license_token = state.config.license_token.clone().unwrap();
        let deployment_id = state.config.deployment_id.clone().unwrap();

        let license_checker_config = LicenseCheckerConfig::from_license_url(
            &license_url,
            license_token,
            deployment_id,
            86400, // 24 hours
        );
        let license_checker = Arc::new(LicenseChecker::new(
            license_checker_config,
            state.pool.clone(),
            state.license_status.clone(),
        ));
        license_checker.load_cached_status().await;

        let lc_handle = license_checker.start();
        state.add_task_handle(lc_handle).await;
        tracing::info!("License checker started (24h interval)");
    } else {
        tracing::info!("License enforcement not configured (LICENSE_URL not set)");
    }

    // === Per-instance tasks ===

    tracing::info!(node_id = %state.node_id, "Node ID for distributed scheduling");

    // Distributed schedulers: detection rules + scheduled jobs via SKIP LOCKED
    tracing::info!("Starting distributed schedulers (detection rules + scheduled jobs)...");
    let distributed_handles = state.start_distributed_schedulers().await;
    for handle in distributed_handles {
        state.add_task_handle(handle).await;
    }

    // Health monitoring
    tracing::info!("Starting health monitoring scheduler...");
    let health_handle = state.start_health_scheduler();
    state.add_task_handle(health_handle).await;

    // meloD config poller (needed for tuning orchestrator AI client).
    // Enterprise only — open tuning runs without AI proposal generation.
    #[cfg(feature = "enterprise")]
    {
        tracing::info!("Starting meloD config poller...");
        let melod_handle = state.start_melod_config_poller();
        state.add_task_handle(melod_handle).await;
    }

    // Rule change listener (needed for distributed detection scheduler cache)
    tracing::info!("Starting rule change listener...");
    let rule_listener_handle = state.start_rule_change_listener();
    state.add_task_handle(rule_listener_handle).await;

    // Case change listener (SSE broadcast via pg_notify).
    // Phase 3.2 (NAN-744): cases moved to enterprise; only register when
    // the enterprise feature is enabled.
    #[cfg(feature = "enterprise")]
    {
        let case_listener_handle = state.start_case_change_listener();
        state.add_task_handle(case_listener_handle).await;
    }

    // === Leader-only tasks ===
    let leader_election_enabled = std::env::var("LEADER_ELECTION_ENABLED")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    if leader_election_enabled {
        tracing::info!("Leader election enabled — starting advisory lock election");
        let election = LeaderElection::new(state.pool.clone(), lock_ids::API_SCHEDULER);
        let mut rx = election.start();

        let leader_state = state.clone();
        let leader_handle = tokio::spawn(async move {
            let mut leader_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
            loop {
                if rx.changed().await.is_err() {
                    tracing::error!("Leader election channel closed unexpectedly");
                    return;
                }

                if !leader_handles.is_empty() {
                    tracing::info!(
                        "Stopping {} leader-only scheduler task(s)",
                        leader_handles.len()
                    );
                    for handle in leader_handles.drain(..) {
                        handle.abort();
                    }
                }

                if *rx.borrow() {
                    leader_handles = leader_state.start_leader_schedulers().await;
                }
            }
        });
        state.add_task_handle(leader_handle).await;
    } else {
        tracing::warn!("Leader election disabled — starting all schedulers unconditionally");
        let handles = state.start_leader_schedulers().await;
        for handle in handles {
            state.add_task_handle(handle).await;
        }
    }

    // OIDC auth-transaction cleanup task. Each /authorize creates a row that's
    // consumed (or expires) within ~10 minutes; without sweeping, expired rows
    // accumulate forever.
    {
        let oidc_repo = state.oidc_repo.clone();
        let oidc_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                match oidc_repo.delete_expired_auth_transactions().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(cleaned = n, "OIDC auth-transaction cleanup completed"),
                    Err(e) => tracing::warn!(error = %e, "OIDC auth-transaction cleanup failed"),
                }
            }
        });
        state.add_task_handle(oidc_handle).await;
        tracing::info!("OIDC auth-transaction cleanup task started (15m interval)");
    }

    // Demo cleanup task
    if let Some(ref demo_service) = state.demo_service {
        let demo_svc = demo_service.clone();
        let demo_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
            loop {
                interval.tick().await;
                match demo_svc.cleanup_expired_sessions().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(cleaned = n, "Demo session cleanup completed"),
                    Err(e) => tracing::warn!(error = %e, "Demo session cleanup failed"),
                }
            }
        });
        state.add_task_handle(demo_handle).await;
        tracing::info!("Demo session cleanup task started (15m interval)");
    }

    // === Health + metrics endpoint ===
    let jobs_port: u16 = std::env::var("JOBS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3001);

    let (app_metrics, prometheus_layer) = AppMetrics::new();

    let health_router = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }))
        .merge(app_metrics.metrics_router())
        .layer(prometheus_layer);

    let shutdown_state = state.clone();
    let shutdown_signal = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Shutdown signal received, stopping background tasks...");
        shutdown_state.shutdown_all_tasks().await;
        tracing::info!("Releasing distributed claims...");
        shutdown_state.release_all_distributed_claims().await;
        tracing::info!("Shutdown complete");
    };

    let bind_address = format!("0.0.0.0:{}", jobs_port);
    tracing::info!("Starting health + metrics endpoint on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    axum::serve(listener, health_router)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}
