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
#[cfg(feature = "enterprise")]
use nanosiem_core::license::checker::LicenseCheckerConfig;
use nanosiem_core::LeaderElection;
#[cfg(feature = "enterprise")]
use nanosiem_core::LicenseChecker;
use std::future::Future;
#[cfg(feature = "enterprise")]
use std::sync::Arc;

/// How often nano-jobs returns freed allocator pages (NAN-3492).
const ALLOCATOR_TRIM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// Below this RSS (idle jobs sits near 100 MiB) a trim is not worth a syscall.
const ALLOCATOR_TRIM_MINIMUM_RSS_BYTES: u64 = 192 * 1024 * 1024;

async fn abort_and_await_leader_tasks(handles: &mut Vec<tokio::task::JoinHandle<()>>) {
    if handles.is_empty() {
        return;
    }

    tracing::info!(
        tasks = handles.len(),
        "Stopping leader-only scheduler tasks"
    );
    for handle in handles.iter() {
        handle.abort();
    }
    while let Some(handle) = handles.pop() {
        match handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::warn!(?error, "Leader-only scheduler task failed"),
        }
    }
}

async fn stop_then_release_claims<S, R>(stop_tasks: S, release_claims: R)
where
    S: Future<Output = ()>,
    R: Future<Output = ()>,
{
    stop_tasks.await;
    release_claims.await;
}

#[tokio::main]
async fn main() -> Result<()> {
    if nanosiem_core::app_features::print_if_requested(nanosiem_api::APP_FEATURES) {
        return Ok(());
    }
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-jobs");
    // NAN-4666: sovereign installation facts gate boot; missing or invalid
    // facts refuse to start.
    nanosiem_core::sovereign_runtime::require_at_boot()
        .map_err(|error| anyhow::anyhow!("Refusing to start: {error}"))?;
    nanosiem_core::crypto::EncryptionService::try_from_env()?;

    tracing::info!("Starting NanoSIEM Jobs Service");

    // NAN-3492: charge rule windows to this process's view memory budget
    // before any scheduler starts, so an oversized window fails its run
    // instead of OOM-killing jobs. nano-api never enables it (its
    // interactive rule triggers stay unbudgeted).
    nanosiem_core::detection::DetectionService::enable_rule_memory_ledger();

    // Load configuration (reuses API config — same env vars)
    let config = ApiConfig::from_env();
    tracing::info!("Configuration loaded");
    let leader_election_enabled = leader_election_configuration()?;

    // Jobs validates rules and scheduled searches against the same canonical
    // field inventory as API/Search. Hosted/shared jobs cannot read a query
    // worker's local generation volume, so install its authenticated schema
    // before AppState performs the fail-closed profile build.
    // NAN-2718: shared mode refuses a process-global schema URL outright
    // (`install_from_env` errors on it) and loads each tenant's schema from its
    // own registry-assigned worker, cached by tenant UUID.
    #[cfg(feature = "enterprise")]
    if config.deployment_mode.is_enterprise_shared() {
        nanosiem_core::schema::worker_schema::refuse_global_schema_in_shared_mode(&|name: &str| {
            std::env::var(name).ok()
        })
        .map_err(|error| anyhow::anyhow!("Refusing to start: {error}"))?;
    }
    let worker_schema_source = if config.canonical_lake_ocsf {
        nanosiem_core::schema::worker_schema::WorkerSchemaSource::install_from_env()
            .await
            .map_err(|error| anyhow::anyhow!("lake schema source unavailable: {error}"))?
    } else {
        None
    };
    #[cfg(feature = "enterprise")]
    if config.canonical_lake_ocsf && config.deployment_mode.is_enterprise_shared() {
        nanosiem_core::schema::tenant_lake_schema::start_for_shared_process().await;
    }

    // Initialize AppState. PostgreSQL is always required; legacy mode also
    // requires ClickHouse, while canonical lake mode connects to no ClickHouse
    // process.
    // SchemaBehind is a hard failure — refuse to start rather than risking
    // corruption against an out-of-date schema. (NAN-607)
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

    // NAN-3492: a trusted-local install's lake tenant must exist in
    // `tenants` before any finding is stamped with it.
    if let Some(tenant) = nanosiem_core::search::lake_cell::ensure_trusted_local_tenant(&state.pool)
        .await
        .map_err(|error| anyhow::anyhow!("Refusing to start: {error}"))?
    {
        tracing::info!(%tenant, "trusted-local tenant registered");
    }

    // Jobs owns tenant-scoped schedulers and mutation paths independently of
    // the HTTP API. Attest the exact live RLS catalog before any task starts;
    // another pod's readiness cannot vouch for this process or connection
    // pool.
    #[cfg(feature = "enterprise")]
    if config.deployment_mode.is_enterprise_shared() {
        // Jobs mounts the same unauthenticated-by-default /metrics router as
        // the API; refuse to expose it token-less in the shared deployment.
        nanosiem_api::metrics::require_metrics_auth_token_for_enterprise_shared(true)?;
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
            &state.pool,
            &runtime_role,
            &owner_role,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "enterprise-shared RLS catalog verification failed; refusing jobs startup: {error}"
            )
        })?;
        tracing::info!("Enterprise-shared jobs RLS catalog verification is green");
    }

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

    // === License enforcement (24h check) ===
    // Enterprise-only: the open edition ships no license / phone-home machinery
    // (NAN-1193). The checker (and its 24h GET /license/status call) is absent.
    #[cfg(feature = "enterprise")]
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

    if let Some(source) = worker_schema_source {
        // NAN-3492: republish each new worker-served field set into the
        // state's profile; installing it alone changes nothing state reads.
        let adopt = state.schema_profile.clone();
        let worker_schema_handle = tokio::spawn(source.run_refresh_loop_with(move || {
            if adopt.adopt_installed_lake_profile() {
                tracing::info!("lake schema profile republished from the worker-served schema");
            }
        }));
        state.add_task_handle(worker_schema_handle).await;
        tracing::info!("Worker-served lake schema refresher started");
    }

    tracing::info!(node_id = %state.node_id, "Node ID for distributed scheduling");

    // AI usage recorder (NAN-1519) — the jobs node runs shadow investigations,
    // closure summaries and other background AI work, so its calls must land in
    // the ai_usage_events ledger too. Per-instance init (enterprise-only).
    #[cfg(feature = "enterprise")]
    {
        nanosiem_enterprise::melod::usage_recorder::init(
            state.pool.clone(),
            state.tenant_ai_rls_runtime.clone(),
        );
        tracing::info!("AI usage recorder started");
    }

    // NAN-3080: install the Prometheus recorder BEFORE any scheduler starts.
    // `metrics` macros bind to whatever recorder is global at call time; the
    // tenant detection runtime's gauges and counters emitted before this
    // point went to the no-op recorder and never reached /metrics.
    let (app_metrics, prometheus_layer) = AppMetrics::new();

    // Distributed schedulers: detection rules + scheduled jobs via SKIP LOCKED
    tracing::info!("Starting distributed schedulers (detection rules + scheduled jobs)...");
    let distributed_handles = state.start_distributed_schedulers().await;
    for handle in distributed_handles {
        state.add_task_handle(handle).await;
    }

    // meloD config poller (needed for tuning orchestrator AI client).
    // Enterprise only — open tuning runs without AI proposal generation.
    #[cfg(feature = "enterprise")]
    {
        tracing::info!("Starting meloD config poller...");
        let melod_handle = state.start_melod_config_poller();
        state.add_task_handle(melod_handle).await;
    }

    // Case SSE clients periodically refetch through authorized endpoints.

    // === Leader-only tasks ===
    if leader_election_enabled {
        tracing::info!("Leader election enabled — starting advisory lock election");
        let election = LeaderElection::new(state.pool.clone(), lock_ids::API_SCHEDULER);
        let leader_shutdown = state.shutdown_token();
        let (mut rx, election_handle) = election.start(leader_shutdown.clone());
        state.add_task_handle(election_handle).await;

        let leader_state = state.clone();
        let leader_handle = tokio::spawn(async move {
            let mut leader_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
            loop {
                tokio::select! {
                    biased;
                    _ = leader_shutdown.cancelled() => {
                        abort_and_await_leader_tasks(&mut leader_handles).await;
                        return;
                    }
                    changed = rx.changed() => {
                        if changed.is_err() {
                            abort_and_await_leader_tasks(&mut leader_handles).await;
                            if !leader_shutdown.is_cancelled() {
                                tracing::error!("Leader election channel closed unexpectedly");
                            }
                            return;
                        }
                    }
                }

                abort_and_await_leader_tasks(&mut leader_handles).await;
                if leader_shutdown.is_cancelled() {
                    return;
                }

                if *rx.borrow() {
                    // NAN-3080: supervised like every registered loop (a
                    // panicking leader scheduler exits the process); the
                    // abort on leadership loss aborts them without exiting.
                    let started = leader_state.start_leader_schedulers().await;
                    leader_handles = leader_state.supervise_tasks("leader_scheduler", started);
                }
            }
        });
        state.add_task_handle(leader_handle).await;
    } else {
        tracing::warn!("Leader election disabled for explicitly declared single-node jobs service");
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
        let shutdown = state.shutdown_token();
        let oidc_handle = tokio::spawn(async move {
            let cleanup = async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
                interval.tick().await; // skip the immediate tick
                loop {
                    interval.tick().await;
                    match oidc_repo.delete_expired_auth_transactions().await {
                        Ok(0) => {}
                        Ok(n) => {
                            tracing::info!(cleaned = n, "OIDC auth-transaction cleanup completed")
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "OIDC auth-transaction cleanup failed")
                        }
                    }
                }
            };

            let _ = shutdown.run_until_cancelled(cleanup).await;
        });
        state.add_task_handle(oidc_handle).await;
        tracing::info!("OIDC auth-transaction cleanup task started (15m interval)");
    }

    // Demo cleanup task
    if let Some(ref demo_service) = state.demo_service {
        let demo_svc = demo_service.clone();
        let shutdown = state.shutdown_token();
        let demo_handle = tokio::spawn(async move {
            let cleanup = async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
                loop {
                    interval.tick().await;
                    match demo_svc.cleanup_expired_sessions().await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(cleaned = n, "Demo session cleanup completed"),
                        Err(e) => tracing::warn!(error = %e, "Demo session cleanup failed"),
                    }
                }
            };

            let _ = shutdown.run_until_cancelled(cleanup).await;
        });
        state.add_task_handle(demo_handle).await;
        tracing::info!("Demo session cleanup task started (15m interval)");
    }

    // NAN-4152: per-tenant demo sessions on the shared stack. Every replica
    // may run it: each session is retired in its own signed tenant
    // transaction that claims the row with SKIP LOCKED.
    #[cfg(feature = "enterprise")]
    if config.deployment_mode.is_enterprise_shared() {
        if let Some(runtime) = state.tenant_ai_rls_runtime.as_ref() {
            let demo = runtime.demo_runtime();
            let control = state.pool.clone();
            let shutdown = state.shutdown_token();
            let shared_demo_handle = tokio::spawn(async move {
                let cleanup = async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
                    loop {
                        interval.tick().await;
                        nanosiem_enterprise::handlers::shared_demo_sessions::run_demo_cleanup_tick(&demo, &control).await;
                    }
                };
                let _ = shutdown.run_until_cancelled(cleanup).await;
            });
            state.add_task_handle(shared_demo_handle).await;
            tracing::info!("Shared demo session cleanup task started (15m interval)");
        } else {
            tracing::warn!("Shared demo session cleanup not started: no signed tenant runtime");
        }
    }

    // NAN-3492: rule windows, lake pages and finding reads free large JSON trees
    // back to glibc, not to the kernel; without a trim the cgroup keeps the
    // peak charged and the next burst stacks on it (nano-search does the same).
    let trim_handle = tokio::spawn(nanosiem_core::allocator_trim::run_allocator_trim_loop(
        "nanosiem-jobs",
        ALLOCATOR_TRIM_INTERVAL,
        ALLOCATOR_TRIM_MINIMUM_RSS_BYTES,
        state.shutdown_token(),
    ));
    state.add_task_handle(trim_handle).await;

    // === Health + metrics endpoint ===
    let jobs_port: u16 = std::env::var("JOBS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3001);

    let health_router = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }))
        .merge(app_metrics.metrics_router())
        .merge(nanosiem_api::hosted_config_router())
        .layer(prometheus_layer);

    let wait_for_shutdown = async {
        match nanosiem_core::shutdown::wait_for_shutdown_signal().await {
            Ok(signal) => tracing::info!(%signal, "Shutdown signal received"),
            Err(error) => tracing::error!(%error, "Shutdown signal handler failed"),
        }
    };

    let bind_address = format!("0.0.0.0:{}", jobs_port);
    tracing::info!("Starting health + metrics endpoint on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    let server_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let graceful_shutdown = server_shutdown.clone();
    let server = axum::serve(listener, health_router).with_graceful_shutdown(async move {
        graceful_shutdown.cancelled().await;
    });
    let cleanup_state = state.clone();
    let cleanup = async move {
        stop_then_release_claims(
            async {
                tracing::info!("Stopping background tasks...");
                cleanup_state.shutdown_all_tasks().await;
            },
            async {
                tracing::info!("Releasing distributed claims...");
                cleanup_state.release_all_distributed_claims().await;
            },
        )
        .await;
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

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| value.to_ascii_lowercase() != "false" && value != "0")
        .unwrap_or(default)
}

fn leader_election_configuration() -> Result<bool> {
    let enabled = env_flag("LEADER_ELECTION_ENABLED", true);
    let single_node = std::env::var("JOBS_SINGLE_NODE")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    validate_leader_election_configuration(enabled, single_node)?;
    Ok(enabled)
}

fn validate_leader_election_configuration(enabled: bool, single_node: bool) -> Result<()> {
    if !enabled && !single_node {
        anyhow::bail!(
            "LEADER_ELECTION_ENABLED=false requires JOBS_SINGLE_NODE=true; refusing to start because unfenced leader schedulers are unsafe in a multi-node jobs deployment"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    struct RunningGuard(Arc<AtomicUsize>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn leader_children_are_aborted_and_awaited() {
        let running = Arc::new(AtomicUsize::new(2));
        let started = Arc::new(tokio::sync::Barrier::new(3));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let task_running = Arc::clone(&running);
            let task_started = Arc::clone(&started);
            handles.push(tokio::spawn(async move {
                let _guard = RunningGuard(task_running);
                task_started.wait().await;
                std::future::pending::<()>().await;
            }));
        }
        started.wait().await;

        abort_and_await_leader_tasks(&mut handles).await;

        assert!(handles.is_empty());
        assert_eq!(running.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn claims_are_released_only_after_tracked_work_stops() {
        let work_running = Arc::new(AtomicBool::new(true));
        let claims_released = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&work_running);
        let observed_running = Arc::clone(&work_running);
        let released = Arc::clone(&claims_released);

        stop_then_release_claims(
            async move {
                tokio::task::yield_now().await;
                stopped.store(false, Ordering::SeqCst);
            },
            async move {
                assert!(!observed_running.load(Ordering::SeqCst));
                released.store(true, Ordering::SeqCst);
            },
        )
        .await;

        assert!(claims_released.load(Ordering::SeqCst));
    }

    #[test]
    fn disabled_election_requires_an_explicit_single_node_declaration() {
        assert!(validate_leader_election_configuration(false, false).is_err());
        assert!(validate_leader_election_configuration(false, true).is_ok());
        assert!(validate_leader_election_configuration(true, false).is_ok());
    }

    #[tokio::test]
    async fn leadership_loss_aborts_and_awaits_owned_work() {
        // Reconciled onto the single retained teardown helper: 1781's
        // stop_leader_tasks was folded into abort_and_await_leader_tasks so the
        // abort-then-await-then-release-claims ordering is preserved.
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let mut handles = vec![tokio::spawn(async move {
            let _signal = DropSignal(Some(dropped_tx));
            std::future::pending::<()>().await;
        })];
        tokio::task::yield_now().await;
        abort_and_await_leader_tasks(&mut handles).await;

        assert!(handles.is_empty());
        assert!(dropped_rx.await.is_ok());
    }
}
