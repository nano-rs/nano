// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM REST API Server
//!
//! Pure HTTP request handling. Background jobs (detection scheduling, signal
//! processing, enrichment sync, tuning, cleanup) run in the separate
//! nanosiem-jobs binary.

use anyhow::Result;
use nanosiem_api::{create_router, ApiConfig, AppMetrics, AppState};
#[cfg(feature = "enterprise")]
use nanosiem_core::license::checker::LicenseCheckerConfig;
#[cfg(feature = "enterprise")]
use nanosiem_core::LicenseChecker;
use std::net::SocketAddr;

fn main() -> Result<()> {
    // NAN-5214: before anything can negotiate TLS with PostgreSQL.
    nanosiem_core::db::tls_provider::install_default_crypto_provider();
    // NAN-4919: the Nano Pipe preview worker. It must run before tracing,
    // configuration, pools or the server exist, with nothing inherited.
    if std::env::args().nth(1).as_deref()
        == Some(nanosiem_core::parsers::pipe::sandbox::WORKER_ARGUMENT)
    {
        return nanosiem_core::parsers::pipe::sandbox::worker_main()
            .map_err(|error| anyhow::anyhow!("{error}"));
    }
    // NAN-5234: the parser-test worker (tenant VRL over sample events). Same
    // rule: dispatched before anything else exists.
    if std::env::args().nth(1).as_deref()
        == Some(nanosiem_core::parsers::test_sandbox::WORKER_ARGUMENT)
    {
        return nanosiem_core::parsers::test_sandbox::worker_main()
            .map_err(|error| anyhow::anyhow!("{error}"));
    }
    // Parser tests in this process run in workers of this executable.
    nanosiem_core::parsers::test_sandbox::register_current_executable();
    // NAN-4919: the Vector tap relay sidecar (the only client of Vector's
    // loopback API). No database, no server state.
    if std::env::args().nth(1).as_deref() == Some(nanosiem_api::pipe_tap_relay::RELAY_ARGUMENT) {
        return nanosiem_api::pipe_tap_relay::relay_main();
    }
    // NAN-4917: query parsing/compilation/evaluation walk the nPL AST
    // recursively on runtime threads. Size worker + blocking stacks for the
    // depth the query complexity budget admits, so a hostile query can never
    // abort the process with a (uncatchable) stack overflow.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(nanosiem_core::query::complexity::RUNTIME_THREAD_STACK_SIZE)
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-api");

    tracing::info!("Starting NanoSIEM API server");
    // Security review 2026-11-08: surface insecure-but-accepted deployment
    // settings (public install token, config delivery on the install token).
    nanosiem_core::deployment_posture::log_posture_at_boot("nano-api");

    // Load configuration
    let config = ApiConfig::from_env();
    tracing::info!(
        "Configuration loaded: host={}, port={}",
        config.host,
        config.port
    );

    // Initialize with DualPool (ClickHouse + PostgreSQL). Both are required;
    // the historical PG-only fallback was removed in NAN-800. A schema-behind
    // error for either store is a hard boot failure. (NAN-607)
    let mut state = match AppState::try_with_dual_pool(config.clone()).await {
        Ok(state) => state,
        Err(nanosiem_core::db::DualPoolError::SchemaBehind(msg))
        | Err(nanosiem_core::db::DualPoolError::PostgresSchemaBehind(msg)) => {
            tracing::error!("Refusing to start: {}", msg);
            return Err(anyhow::anyhow!("{}", msg));
        }
        Err(e) => {
            tracing::error!("Refusing to start: DualPool initialization failed: {}", e);
            return Err(anyhow::anyhow!("DualPool initialization failed: {}", e));
        }
    };

    // Establish one explicit admission authority before any licensed route or
    // worker starts. A partial online tuple and a never-checked fresh install
    // fail closed; no configuration falls through to C05/legacy authority.
    #[cfg(feature = "enterprise")]
    initialize_license_admission(&state).await;

    // Initialize demo service if DEPLOYMENT_MODE=demo
    if let Err(e) = state.init_demo_if_enabled().await {
        tracing::warn!(
            "Failed to initialize demo service: {}. Demo mode disabled.",
            e
        );
    }

    tracing::info!("Running in dual-mode (ClickHouse + PostgreSQL)");

    // NAN-4933: record this process's credential key ring (refuses to start
    // if a key id was reused for different material) and keep its ring
    // membership fresh so a key it writes with is never retired under it.
    state.register_credential_key_ring("api").await?;
    let credential_membership = state.start_credential_key_membership("api");
    state.add_task_handle(credential_membership).await;

    // === One-time PG→ClickHouse lookup row-data backfill (NAN-1581 Phase 2/3) ===
    // Only when LOOKUP_STORAGE_BACKEND=clickhouse: migrate every existing
    // Postgres `lookup_<name>` table's rows into the shared ClickHouse
    // `lookup_rows` table BEFORE the service serves lookup reads from CH (lookup
    // data has no upstream re-sync). Multi-pod-safe via a transactional claim in
    // `lookup_backfill_state`; per-table done-markers make it resumable; re-runs
    // are dedup-safe. The default (postgres) path skips this entirely.
    if matches!(
        nanosiem_core::lookup::LookupStorageBackend::from_env(),
        nanosiem_core::lookup::LookupStorageBackend::ClickHouse
    ) {
        tracing::info!("LOOKUP_STORAGE_BACKEND=clickhouse — running lookup backfill check...");
        match nanosiem_core::lookup::backfill_pg_to_clickhouse(
            state.pool.clone(),
            state.dual_pool.clickhouse().clone(),
        )
        .await
        {
            Ok(report) if report.ran => {
                let mismatches = report.mismatches().len();
                if mismatches > 0 {
                    tracing::error!(
                        "Lookup backfill completed with {} count mismatch(es); manual review required",
                        mismatches
                    );
                } else {
                    tracing::info!(
                        "Lookup backfill complete: {} table(s) processed",
                        report.tables.len()
                    );
                }
            }
            Ok(_) => {
                // This pod did NOT win the claim. Another pod may still be copying
                // the snapshot — if we boot straight into serving CH lookup reads
                // now, we'd serve an incomplete table. Wait for the global claim to
                // be released (backfill done) before proceeding to axum::serve.
                // Bounded so a stuck claim can't hang the pod forever; if it
                // elapses we fail readiness rather than serve stale data.
                const BACKFILL_POLL_INTERVAL: std::time::Duration =
                    std::time::Duration::from_secs(2);
                const BACKFILL_WAIT_TIMEOUT: std::time::Duration =
                    std::time::Duration::from_secs(300);

                if nanosiem_core::lookup::is_backfill_in_progress(&state.pool).await {
                    tracing::info!(
                        "Lookup backfill owned by another pod — waiting up to {}s for completion before serving CH lookup reads...",
                        BACKFILL_WAIT_TIMEOUT.as_secs()
                    );
                    let deadline = std::time::Instant::now() + BACKFILL_WAIT_TIMEOUT;
                    loop {
                        tokio::time::sleep(BACKFILL_POLL_INTERVAL).await;
                        if !nanosiem_core::lookup::is_backfill_in_progress(&state.pool).await {
                            tracing::info!(
                                "Lookup backfill completed by owning pod; proceeding to serve."
                            );
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
                } else {
                    tracing::info!("Lookup backfill already complete; proceeding.");
                }
            }
            Err(e) => tracing::error!(
                "Lookup backfill failed: {}. Lookup reads from ClickHouse may be incomplete.",
                e
            ),
        }
    }

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
    // Startup reconciliation is an explicit trusted system workflow. User
    // requests receive a principal-derived grant in the source-config handler.
    match state
        .source_config_service
        .reconcile_on_boot(nanosiem_core::auth::CredentialUseGrant::system())
        .await
    {
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

    // NAN-5132: a deploy job a stopped API process left running never
    // finishes; report it interrupted (the boot render above rewrote the
    // Vector config from the database) and prune old jobs.
    {
        let deploy_jobs = state.log_source_deploy_jobs.clone();
        let holds_pool = state.pool.clone();
        tokio::spawn(async move {
            // NAN-5132 (PR 5): a two-phase deploy that died between its phases
            // left its source parked; release holds older than any deploy.
            if let Err(error) =
                nanosiem_core::log_sources::activation::release_stale(&holds_pool).await
            {
                tracing::warn!(%error, "Releasing stale log-source activation holds failed");
            }
            match deploy_jobs.recover().await {
                Ok((interrupted, pruned)) => {
                    tracing::info!(interrupted, pruned, "Deploy job recovery done")
                }
                Err(error) => tracing::warn!(%error, "Deploy job recovery failed"),
            }
        });
    }

    // Publish only a complete DB-derived generation. The same reconciler runs
    // on every API replica so a new emptyDir can recover the committed
    // generation; the PostgreSQL CAS prevents stale replicas from advancing it.
    #[cfg(not(feature = "enterprise"))]
    {
        match state.reconcile_vector_config_publication().await {
            Ok(outcome) => tracing::info!(?outcome, "Vector config publication reconciled"),
            Err(error) => tracing::warn!(
                %error,
                "Initial Vector config publication failed; the background reconciler will retry"
            ),
        }
        state.install_generation_delivery();
        let vector_config_handle = state.start_vector_config_publication_reconciler();
        state.add_task_handle(vector_config_handle).await;
        tracing::info!("Vector config publication reconciler started");

        // NAN-4907: keep Vector's hashed ingest tokens file in step with the
        // database and sample per-token "last used".
        let ingest_tokens_handle = state.ingest_token_service.clone().spawn_reconcile();
        state.add_task_handle(ingest_tokens_handle).await;
        tracing::info!(
            tokens_file = %state.ingest_token_service.tokens_file().display(),
            "Ingest token reconcile started"
        );
    }
    #[cfg(feature = "enterprise")]
    {
        // Ingest is part of the open/core continuity boundary and remains
        // available after a commercial license hard stop.
        state.install_generation_delivery();
        let vector_config_handle = state.start_vector_config_publication_reconciler();
        state.add_task_handle(vector_config_handle).await;
        let ingest_tokens_handle = state.ingest_token_service.clone().spawn_reconcile();
        state.add_task_handle(ingest_tokens_handle).await;
        tracing::info!("Open/core ingest reconcilers started");
    }

    // === License status poller (reads cached status from PG, written by nanosiem-jobs) ===
    // Enterprise-only: the open edition ships no license / phone-home machinery
    // and runs unrestricted by construction (NAN-1193).
    #[cfg(feature = "enterprise")]
    if state.config.is_license_enabled() {
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
                        *poll_state.license_status.write().await = status.for_online_admission();
                    }
                    Err(e) => tracing::debug!("License status poll failed: {}", e),
                }
            }
        });
        state.add_task_handle(poll_handle).await;
        tracing::info!("License status poller started (5m interval, reads from PG)");
    } else if state.config.online_license_config().is_ok() {
        // The single C05 authority task durably observes every 30 seconds.
        // Request handlers consume only its cached snapshot.
        let refresh_state = state.clone();
        let refresh_handle = tokio::spawn(async move {
            run_sovereign_license_refresh(refresh_state).await;
        });
        state.add_task_handle(refresh_handle).await;
        tracing::info!("C05/legacy license refresh started (30s interval)");
    } else {
        tracing::error!("Incomplete online license configuration remains locked until restart");
    }

    // === Per-instance tasks (API-specific) ===

    // meloD config poller (per-instance AI config, needed for API requests on
    // any pod). Enterprise only — the poller lives on the meloD service.
    #[cfg(feature = "enterprise")]
    {
        let supervisor = state.start_component_worker_supervisor(
            nanosiem_api::license_admission::WorkerCapability::Melod,
            "api_melod",
            |state| {
                // The recorder is an idle sink when no licensed producer is
                // running. Initializing it here makes a later hot C05 import
                // immediately usable; the component supervisor controls the
                // actual meloD poller and all producing routes are guarded.
                nanosiem_enterprise::melod::usage_recorder::init(state.pool.clone());
                vec![state.start_melod_config_poller()]
            },
        );
        state.add_task_handle(supervisor).await;
    }

    // Case change listener (per-instance SSE broadcast via pg_notify).
    // Phase 3.2 (NAN-744): cases moved to enterprise; the SSE listener
    // only spins up when the enterprise feature is enabled.
    #[cfg(feature = "enterprise")]
    {
        let supervisor = state.start_component_worker_supervisor(
            nanosiem_api::license_admission::WorkerCapability::Cases,
            "api_cases",
            |state| {
                vec![
                    state.start_case_change_listener(),
                    state.start_shadow_investigation_recovery(),
                ]
            },
        );
        state.add_task_handle(supervisor).await;
    }

    // Initialize metrics
    tracing::info!("Initializing Prometheus metrics...");
    let (app_metrics, prometheus_layer) = AppMetrics::new();
    tracing::info!("Prometheus metrics initialized");

    // Create router with metrics layer
    let app = create_router(state.clone()).layer(prometheus_layer).merge(
        app_metrics
            .metrics_router(nanosiem_core::auth::service_credential::LoopbackPolicy::RequireToken),
    );

    let wait_for_shutdown = async {
        match nanosiem_core::shutdown::wait_for_shutdown_signal().await {
            Ok(signal) => tracing::info!(%signal, "Shutdown signal received"),
            Err(error) => tracing::error!(%error, "Shutdown signal handler failed"),
        }
    };

    // Start server with ConnectInfo support for capturing client IP addresses
    let bind_address = config.bind_address();
    tracing::info!("Starting server on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let server_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let graceful_shutdown = server_shutdown.clone();
    let server = axum::serve(listener, make_service).with_graceful_shutdown(async move {
        graceful_shutdown.cancelled().await;
    });
    let cleanup_state = state.clone();
    let cleanup = async move {
        tracing::info!("Stopping background tasks...");
        cleanup_state.shutdown_all_tasks().await;
        tracing::info!("Shutdown complete");
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

#[cfg(feature = "enterprise")]
async fn initialize_license_admission(state: &AppState) {
    match state.config.online_license_config() {
        Ok(Some(online)) => {
            let checker = LicenseChecker::new(
                LicenseCheckerConfig::from_license_url(
                    &online.url,
                    online.token,
                    online.deployment_id,
                    86_400,
                ),
                state.pool.clone(),
                state.license_status.clone(),
            );
            if let Err(error) = checker.initialize().await {
                tracing::error!(%error, "Initial online license check failed; using only a previously successful bounded cache");
            }
        }
        Ok(None) => refresh_sovereign_license_status(state).await,
        Err(error) => {
            tracing::error!(%error, "Incomplete online license configuration; failing closed");
            let snapshot = nanosiem_api::license_admission::OfflineLicenseSnapshot::Unavailable(
                error.to_string(),
            );
            *state.license_status.write().await = snapshot.cached_status();
            *state.offline_license_snapshot.write().await = snapshot;
        }
    }
}

#[cfg(feature = "enterprise")]
async fn refresh_sovereign_license_status(state: &AppState) {
    match nanosiem_api::license_admission::refresh_offline_snapshot(state, true).await {
        Ok(snapshot) => {
            if let Some(grace) = snapshot.legacy_grace() {
                tracing::warn!(
                    grace_until = %grace.grace_until,
                    "Legacy offline license upgrade grace active; import a C05 license"
                );
            } else if let Some(view) = snapshot.c05_view() {
                if !view.valid {
                    tracing::warn!(
                        reason = view
                            .refusal
                            .as_deref()
                            .or(view.notice.as_deref())
                            .unwrap_or("C05 license refused"),
                        "Air-gapped deployment is locked by the C05 authority"
                    );
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "C05 authority refresh failed");
            nanosiem_api::license_admission::record_refresh_failure(&state, &error).await;
        }
    }
}

#[cfg(feature = "enterprise")]
async fn run_sovereign_license_refresh(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.tick().await;
    loop {
        interval.tick().await;
        refresh_sovereign_license_status(&state).await;
    }
}
