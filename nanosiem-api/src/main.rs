// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM REST API Server
//!
//! Pure HTTP request handling. Background jobs (detection scheduling, signal
//! processing, enrichment sync, tuning, cleanup) run in the separate
//! nanosiem-jobs binary.

use anyhow::Result;
use nanosiem_api::{create_router, ApiConfig, AppMetrics, AppState};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-api");

    tracing::info!("Starting NanoSIEM API server");

    // Load configuration
    let config = ApiConfig::from_env();
    tracing::info!(
        "Configuration loaded: host={}, port={}",
        config.host,
        config.port
    );

    // Initialize with DualPool (ClickHouse + PostgreSQL). Both are required;
    // the historical PG-only fallback was removed in NAN-800. SchemaBehind
    // means ClickHouse is reachable but missing migrations — refuse to start
    // rather than risk corruption against an out-of-date schema. (NAN-607)
    let mut state = match AppState::try_with_dual_pool(config.clone()).await {
        Ok(state) => state,
        Err(nanosiem_core::db::DualPoolError::SchemaBehind(msg)) => {
            tracing::error!("Refusing to start: {}", msg);
            return Err(anyhow::anyhow!("{}", msg));
        }
        Err(e) => {
            tracing::error!("Refusing to start: DualPool initialization failed: {}", e);
            return Err(anyhow::anyhow!("DualPool initialization failed: {}", e));
        }
    };

    // Initialize demo service if DEPLOYMENT_MODE=demo
    if let Err(e) = state.init_demo_if_enabled().await {
        tracing::warn!(
            "Failed to initialize demo service: {}. Demo mode disabled.",
            e
        );
    }

    tracing::info!("Running in dual-mode (ClickHouse + PostgreSQL)");

    // Initialize meloD AI service if configured. The reload path lives in
    // the enterprise crate; open-core builds simply skip AI initialization.
    #[cfg(feature = "enterprise")]
    {
    tracing::info!("Checking meloD configuration...");
    match state.reload_melod_service().await {
        Ok(true) => {
            tracing::info!("meloD AI service initialized");
        }
        Ok(false) => {
            tracing::info!("meloD AI service not configured (disabled or no credentials)");
        }
        Err(e) => {
            tracing::warn!(
                "Failed to initialize meloD AI service: {}. AI features disabled.",
                e
            );
        }
    }
    }

    // Deploy Vector pipeline configs (parsers, router, combiner, pipeline, sink).
    // In Docker Compose these exist on disk from the repo. In k8s, the dirs are empty
    // emptyDirs so we must generate them on startup before source configs can deploy.
    tracing::info!("Deploying Vector pipeline configs...");
    match state.parser_service.deploy_to_vector().await {
        Ok(()) => tracing::info!("Vector pipeline configs deployed"),
        Err(e) => tracing::warn!(
            "Failed to deploy Vector pipeline configs: {}. Ingestion pipeline may be incomplete.",
            e
        ),
    }

    // Deploy all enabled source configurations to sync DB state with Vector config files.
    // This ensures HTTP ingestion is live on first boot (migration seeds it as deployed=true
    // but Vector config files need to be written).
    tracing::info!("Syncing source configuration deployments...");
    match state.source_config_service.deploy_all().await {
        Ok(results) => {
            let ok = results.iter().filter(|r| r.success).count();
            let fail = results.iter().filter(|r| !r.success).count();
            tracing::info!(
                "Source config sync complete: {} deployed, {} failed",
                ok,
                fail
            );
        }
        Err(e) => {
            tracing::warn!("Failed to sync source config deployments: {}. Ingestion may not work until manually deployed.", e);
        }
    }

    // Initialize real-time evaluator (load rules for real-time detection)
    tracing::info!("Initializing real-time evaluator...");
    if let Err(e) = state.init_realtime_evaluator().await {
        tracing::warn!(
            "Failed to initialize real-time evaluator: {}. Real-time detection disabled.",
            e
        );
    } else {
        tracing::info!("Real-time evaluator initialized");
    }

    // === License status poller (reads cached status from PG, written by nanosiem-jobs) ===
    if state.config.is_license_enabled() {
        let license_repo = nanosiem_core::LicenseRepository::new(state.pool.clone());
        // Load cached status on startup
        match license_repo.get_status().await {
            Ok(status) => {
                *state.license_status.write().await = status;
                tracing::info!("Loaded cached license status from database");
            }
            Err(e) => tracing::warn!("Failed to load cached license status: {}", e),
        }
        // Poll for updates every 5 minutes (jobs service writes, API reads)
        let poll_state = state.clone();
        let poll_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.tick().await; // Skip initial tick (already loaded above)
            loop {
                interval.tick().await;
                let repo = nanosiem_core::LicenseRepository::new(poll_state.pool.clone());
                match repo.get_status().await {
                    Ok(status) => {
                        *poll_state.license_status.write().await = status;
                    }
                    Err(e) => tracing::debug!("License status poll failed: {}", e),
                }
            }
        });
        state.add_task_handle(poll_handle).await;
        tracing::info!("License status poller started (5m interval, reads from PG)");
    } else {
        tracing::info!(
            "License enforcement not configured (LICENSE_URL not set) — running unrestricted"
        );
    }

    // === Per-instance tasks (API-specific) ===

    // meloD config poller (per-instance AI config, needed for API requests on
    // any pod). Enterprise only — the poller lives on the meloD service.
    #[cfg(feature = "enterprise")]
    {
        tracing::info!("Starting meloD config poller...");
        let melod_handle = state.start_melod_config_poller();
        state.add_task_handle(melod_handle).await;
        tracing::info!("meloD config poller started (30s interval)");
    }

    // Rule change listener (per-instance cache invalidation via pg_notify)
    tracing::info!("Starting rule change listener...");
    let rule_listener_handle = state.start_rule_change_listener();
    state.add_task_handle(rule_listener_handle).await;
    tracing::info!("Rule change listener started");

    // Case change listener (per-instance SSE broadcast via pg_notify).
    // Phase 3.2 (NAN-744): cases moved to enterprise; the SSE listener
    // only spins up when the enterprise feature is enabled.
    #[cfg(feature = "enterprise")]
    {
        tracing::info!("Starting case change listener...");
        let case_listener_handle = state.start_case_change_listener();
        state.add_task_handle(case_listener_handle).await;
        tracing::info!("Case change listener started");
    }

    // Initialize metrics
    tracing::info!("Initializing Prometheus metrics...");
    let (app_metrics, prometheus_layer) = AppMetrics::new();
    tracing::info!("Prometheus metrics initialized");

    // Create router with metrics layer
    let app = create_router(state.clone())
        .layer(prometheus_layer)
        .merge(app_metrics.metrics_router());

    // Set up graceful shutdown signal handler
    let shutdown_state = state.clone();
    let shutdown_signal = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Shutdown signal received, stopping background tasks...");
        shutdown_state.shutdown_all_tasks().await;
        tracing::info!("Shutdown complete");
    };

    // Start server with ConnectInfo support for capturing client IP addresses
    let bind_address = config.bind_address();
    tracing::info!("Starting server on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}
