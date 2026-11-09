// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Background Jobs Service
//!
//! Runs all background tasks (detection scheduling, signal processing,
//! enrichment sync, tuning, cleanup, etc.) separately from the HTTP API.
//! This enables independent deploy cycles, resource isolation, and
//! cleaner failure domains.

use anyhow::Result;
use nanosiem_api::{ApiConfig, AppMetrics, AppState};
use nanosiem_core::leader::{lock_ids, LeaderFence, LeaderHooks, LeaderTiming};
#[cfg(feature = "enterprise")]
use nanosiem_core::license::checker::LicenseCheckerConfig;
use nanosiem_core::LeaderElection;
#[cfg(feature = "enterprise")]
use nanosiem_core::LicenseChecker;
use std::future::Future;
#[cfg(feature = "enterprise")]
use std::sync::Arc;

/// The leader-only schedulers, started on election and stopped (aborted and
/// awaited) before the lease can pass to another instance.
struct JobsLeaderTasks {
    state: AppState,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl LeaderHooks for JobsLeaderTasks {
    async fn elected(&mut self, epoch: i64) {
        tracing::info!(epoch, node_id = %self.state.node_id, "Jobs leader elected; starting leader-only schedulers");
        // NAN-3080: supervised like every registered loop (a panicking leader
        // scheduler exits the process); the abort on leadership loss aborts
        // them without exiting.
        let started = self.state.start_leader_schedulers().await;
        self.handles = self.state.supervise_tasks("leader_scheduler", started);
    }

    async fn stepped_down(&mut self) {
        abort_and_await_leader_tasks(&mut self.handles).await;
    }
}

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

fn main() -> Result<()> {
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
    // NAN-4933: `nanosiem-jobs credential-keys <status|rewrap|retire ID>` is
    // the operator CLI for the credential key ring (same env as the service).
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("credential-keys") {
        return credential_keys_cli(&args[1..]).await;
    }
    if args.first().map(String::as_str) == Some("ingest-watchdog") {
        return ingest_watchdog_cli(&args[1..]).await;
    }
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("nanosiem-jobs");

    tracing::info!("Starting NanoSIEM Jobs Service");
    // Security review 2026-11-08: surface insecure-but-accepted deployment
    // settings (public install token, config delivery on the install token).
    nanosiem_core::deployment_posture::log_posture_at_boot("nano-jobs");

    // Load configuration (reuses API config — same env vars)
    let config = ApiConfig::from_env();
    tracing::info!("Configuration loaded");
    let leader_election_enabled = leader_election_configuration()?;

    // Initialize AppState with DualPool. Both ClickHouse and PostgreSQL are
    // required; the historical PG-only fallback was removed in NAN-800.
    // A schema-behind error for either store is a hard boot failure. (NAN-607)
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

    // NAN-4933: leader-only writes are fenced by the jobs lease epoch.
    if leader_election_enabled {
        state.leader_fence = LeaderFence::armed(lock_ids::API_SCHEDULER);
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
    if let Ok(Some(online)) = state.config.online_license_config() {
        let license_checker_config = LicenseCheckerConfig::from_license_url(
            &online.url,
            online.token,
            online.deployment_id,
            86400, // 24 hours
        );
        let license_checker = Arc::new(LicenseChecker::new(
            license_checker_config,
            state.pool.clone(),
            state.license_status.clone(),
        ));
        if let Err(error) = license_checker.initialize().await {
            tracing::error!(%error, "Initial online licence check failed; licensed workers remain fail-closed without a successful bounded cache");
        }

        let lc_handle = license_checker.start();
        state.add_task_handle(lc_handle).await;
        tracing::info!("License checker started (24h interval)");
    } else if state.config.online_license_config().is_ok() {
        match nanosiem_api::license_admission::refresh_offline_snapshot(&state, false).await {
            Ok(snapshot) if snapshot.legacy_grace().is_some() => tracing::warn!(
                "Legacy offline licence upgrade grace active in jobs; import a C05 licence"
            ),
            Ok(_) => tracing::info!("Loaded read-only C05 component admission for jobs"),
            Err(error) => {
                tracing::error!(%error, "C05 admission unavailable in jobs; workers fail closed");
                let snapshot = nanosiem_api::license_admission::unavailable_snapshot(&error);
                *state.license_status.write().await = snapshot.cached_status();
                *state.offline_license_snapshot.write().await = snapshot;
            }
        }
        let refresh_state = state.clone();
        let refresh_handle = tokio::spawn(async move {
            run_read_only_sovereign_license_refresh(refresh_state).await;
        });
        state.add_task_handle(refresh_handle).await;
        tracing::info!("Read-only C05/legacy jobs admission refresh started (30s interval)");
    } else {
        let error = state
            .config
            .online_license_config()
            .expect_err("branch checked incomplete configuration");
        tracing::error!(%error, "Incomplete online licence configuration; failing closed");
        let snapshot =
            nanosiem_api::license_admission::OfflineLicenseSnapshot::Unavailable(error.to_string());
        *state.license_status.write().await = snapshot.cached_status();
        *state.offline_license_snapshot.write().await = snapshot;
    }

    // NAN-4933: credential key ring registration + membership (every node).
    state.register_credential_key_ring("jobs").await?;
    let credential_membership = state.start_credential_key_membership("jobs");
    state.add_task_handle(credential_membership).await;

    // === Per-instance tasks ===

    tracing::info!(node_id = %state.node_id, "Node ID for distributed scheduling");

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
        let supervisor = state.start_component_worker_supervisor(
            nanosiem_api::license_admission::WorkerCapability::Melod,
            "jobs_melod",
            |state| {
                nanosiem_enterprise::melod::usage_recorder::init(state.pool.clone());
                vec![state.start_melod_config_poller()]
            },
        );
        state.add_task_handle(supervisor).await;
    }

    // Enterprise extension workers (generic seam; nothing named here).
    #[cfg(feature = "enterprise")]
    {
        let supervisor = state.start_component_worker_supervisor(
            nanosiem_api::license_admission::WorkerCapability::Soar,
            "jobs_soar",
            |state| nanosiem_enterprise::handlers::extension_jobs(state, state.shutdown_token()),
        );
        state.add_task_handle(supervisor).await;
    }

    // Case change listener (SSE broadcast via pg_notify).
    // Phase 3.2 (NAN-744): cases moved to enterprise; only register when
    // the enterprise feature is enabled.
    #[cfg(feature = "enterprise")]
    {
        let supervisor = state.start_component_worker_supervisor(
            nanosiem_api::license_admission::WorkerCapability::Cases,
            "jobs_cases",
            |state| {
                vec![
                    state.start_case_change_listener(),
                    state.start_shadow_investigation_recovery(),
                ]
            },
        );
        state.add_task_handle(supervisor).await;
    }

    // === Leader-only tasks ===
    if leader_election_enabled {
        // NAN-4933 (port of main NAN-4699 step 4): a PG lease. Renew 2 s,
        // self-fence within 5 s of a failed renew, a stale holder evicted
        // after 20 s, so a warm standby takes over within ~28 s of a hard
        // leader death (2 s after a graceful stop). Each acquisition bumps the
        // lease epoch that leader-only writes check (core leader.rs).
        let timing = LeaderTiming::JOBS.with_env_overrides();
        tracing::info!(
            heartbeat_secs = timing.heartbeat.as_secs(),
            timeout_secs = timing.database_timeout.as_secs(),
            retry_secs = timing.retry.as_secs(),
            stale_secs = ?timing.stale_after.map(|stale| stale.as_secs()),
            "Leader election enabled — PostgreSQL advisory-lock lease"
        );
        let election = LeaderElection::new(state.pool.clone(), lock_ids::API_SCHEDULER)
            .with_timing(timing)
            .with_fence(state.leader_fence.clone(), state.node_id.clone());
        let election_handle = election.spawn_with(
            state.shutdown_token(),
            JobsLeaderTasks {
                state: state.clone(),
                handles: Vec::new(),
            },
        );
        state.add_task_handle(election_handle).await;
    } else {
        tracing::warn!("Leader election disabled for explicitly declared single-node jobs service");
        // Same fatal-on-return policy as the elected path (NAN-4902 review);
        // registering the supervisors keeps them under shutdown's abort.
        let started = state.start_leader_schedulers().await;
        for handle in state.supervise_tasks("leader_scheduler", started) {
            state.add_task_handle(handle).await;
        }
    }

    // OIDC auth-transaction cleanup task. Each /authorize creates a row that's
    // consumed (or expires) within ~10 minutes; without sweeping, expired rows
    // accumulate forever.
    #[cfg(feature = "enterprise")]
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
        .merge(app_metrics.metrics_router(
            nanosiem_core::auth::service_credential::LoopbackPolicy::AllowWhenUnconfigured,
        ))
        .layer(prometheus_layer);

    let wait_for_shutdown = async {
        match nanosiem_core::shutdown::wait_for_shutdown_signal().await {
            Ok(signal) => tracing::info!(%signal, "Shutdown signal received"),
            Err(error) => tracing::error!(%error, "Shutdown signal handler failed"),
        }
    };

    // NAN-2042: the jobs listener is private. It binds loopback unless the
    // operator widens it with JOBS_BIND_ADDR (e.g. a Prometheus scrape on the
    // pod network, which must then also present NANO_SERVICE_TOKEN).
    let bind_address = nanosiem_core::auth::service_credential::private_bind_addr(
        std::env::var(nanosiem_core::auth::service_credential::JOBS_BIND_ADDR_ENV)
            .ok()
            .as_deref(),
        jobs_port,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if !bind_address.ip().is_loopback()
        && !nanosiem_core::auth::service_credential::ServiceCredential::from_env().is_configured()
    {
        tracing::warn!(
            %bind_address,
            "jobs listener is on a non-loopback address without NANO_SERVICE_TOKEN; /metrics will refuse every remote caller"
        );
    }
    tracing::info!("Starting health + metrics endpoint on {}", bind_address);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    let server_shutdown = nanosiem_core::shutdown::ShutdownToken::new();
    let graceful_shutdown = server_shutdown.clone();
    let server = axum::serve(
        listener,
        health_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
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

#[cfg(feature = "enterprise")]
async fn run_read_only_sovereign_license_refresh(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.tick().await;
    loop {
        interval.tick().await;
        if let Err(error) =
            nanosiem_api::license_admission::refresh_offline_snapshot(&state, false).await
        {
            tracing::error!(%error, "C05 jobs admission refresh failed; workers fail closed");
            let snapshot = nanosiem_api::license_admission::unavailable_snapshot(&error);
            *state.license_status.write().await = snapshot.cached_status();
            *state.offline_license_snapshot.write().await = snapshot;
        }
    }
}

/// Credential key ring CLI. Prints JSON (ids, fingerprints, counts; never key
/// material) and exits non-zero on a refused retirement.
async fn credential_keys_cli(args: &[String]) -> Result<()> {
    use nanosiem_core::crypto::rotation::{self, CredentialKeyRepository};
    let usage = "usage: nanosiem-jobs credential-keys <status | rewrap | retire KEY_ID | enforce>";
    let config = ApiConfig::from_env();
    let cipher = nanosiem_core::crypto::EncryptionService::try_from_env()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // The CLI's re-wrap writes secrets: declare its write key like every pool.
    let pool = rotation::declare_write_key(
        sqlx::postgres::PgPoolOptions::new().max_connections(2),
        cipher.active_key_id().to_owned(),
    )
    .connect(&config.database_url)
    .await
    .map_err(|e| anyhow::anyhow!("connect to PostgreSQL: {e}"))?;
    let repo = CredentialKeyRepository::new(pool.clone());
    let node_id = format!("cli-{}", std::process::id());
    // Codex fence review P1: the CLI never registered its ring, so prove its
    // key bytes are the registered ones before touching any secret.
    repo.verify_ring(&cipher).await?;
    let output = match args.first().map(String::as_str) {
        Some("status") => serde_json::json!({
            "active_key_id": cipher.active_key_id(),
            "warnings": nanosiem_api::handlers::credential_keys::ring_warnings(&cipher.ring_keys()),
            "write_fence_enforced": repo.fence_enforced().await?,
            "ring": cipher.ring_keys(),
            "known_keys": repo.known_keys().await?,
            "usage": rotation::scan(&pool, &cipher).await?,
            "members": repo.members().await?,
            "recent_runs": repo.recent_runs(10).await?,
        }),
        Some("rewrap") => {
            let (outcome, usage) = rotation::run_pass(&repo, &cipher, "manual", &node_id).await?;
            serde_json::json!({ "outcome": outcome, "usage": usage })
        }
        Some("retire") => {
            let key_id = args.get(1).ok_or_else(|| anyhow::anyhow!(usage))?;
            let report = repo.retire(&cipher, key_id, None).await?;
            serde_json::json!({ "key_id": key_id, "retired": true, "usage": report })
        }
        Some("enforce") => {
            let flipped = repo.enforce_fence("cli").await?;
            serde_json::json!({ "write_fence_enforced": true, "changed": flipped })
        }
        _ => anyhow::bail!(usage),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Operator control for the leader-owned ClickHouse ingest watchdog. Manual
/// start intentionally retains manual mode; only `auto` returns ownership to
/// the watchdog.
async fn ingest_watchdog_cli(args: &[String]) -> Result<()> {
    use nanosiem_core::ingest_watchdog::{IngestWatchdog, WatchdogOperatorAction};

    let usage = "usage: nanosiem-jobs ingest-watchdog <status|manual-stop|manual-start|auto>";
    let action = match args.first().map(String::as_str) {
        Some("status") => WatchdogOperatorAction::Status,
        Some("manual-stop") => WatchdogOperatorAction::ManualStop,
        Some("manual-start") => WatchdogOperatorAction::ManualStart,
        Some("auto") => WatchdogOperatorAction::Auto,
        _ => anyhow::bail!(usage),
    };
    let watchdog = IngestWatchdog::from_env().await?;
    let output = watchdog.operator(action).await?;
    println!("{}", serde_json::to_string_pretty(&output)?);
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
