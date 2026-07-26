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
        .deploy_all(nanosiem_core::auth::CredentialUseGrant::system())
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

    // Publish only a complete DB-derived generation. The same reconciler runs
    // on every API replica so a new emptyDir can recover the committed
    // generation; the PostgreSQL CAS prevents stale replicas from advancing it.
    match state.reconcile_vector_config_publication().await {
        Ok(outcome) => tracing::info!(?outcome, "Vector config publication reconciled"),
        Err(error) => tracing::warn!(
            %error,
            "Initial Vector config publication failed; the background reconciler will retry"
        ),
    }
    let vector_config_handle = state.start_vector_config_publication_reconciler();
    state.add_task_handle(vector_config_handle).await;
    tracing::info!("Vector config publication reconciler started");

    // === License status poller (reads cached status from PG, written by nanosiem-jobs) ===
    // Enterprise-only: the open edition ships no license / phone-home machinery
    // and runs unrestricted by construction (NAN-1193).
    #[cfg(feature = "enterprise")]
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
    } else if state.config.airgap {
        // === Air-gapped install (AIRGAP_MODE on, no LICENSE_URL) — FAIL CLOSED ===
        // There is no phone-home path here (LICENSE_URL is unset, so we never
        // start the poller above). Enforcement instead rides on a signed offline
        // license bundle imported via POST /api/airgap/license/import, which
        // persists a singleton `license_status` row with `offline = TRUE` and a
        // hard `expires_at`. We load that persisted row so an imported license
        // survives restarts, then decide the boot status:
        //   - valid, non-expired offline license  -> that status (enforced by
        //     license_guard + effective(now), incl. local self-expiry)
        //   - anything else (no row / not offline / expired) -> Locked, so the
        //     install is unusable until an operator imports a license.
        let license_repo = nanosiem_core::LicenseRepository::new(state.pool.clone());
        let persisted = match license_repo.get_status().await {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!(
                    "Failed to load persisted air-gap license status: {} — failing closed",
                    e
                );
                nanosiem_core::license::LicenseStatus::default()
            }
        };
        let decided = airgap_boot_license_status(persisted, chrono::Utc::now());
        if decided.state == nanosiem_core::license::LicenseState::Locked {
            tracing::warn!(
                reason = decided.locked_reason.as_deref().unwrap_or(""),
                "Air-gapped deployment is LOCKED — import a signed offline license via /settings/airgap-import to unlock"
            );
        } else {
            tracing::info!(
                tier = decided.tier.as_deref().unwrap_or("unknown"),
                expires_at = decided.expires_at.map(|e| e.to_rfc3339()).as_deref().unwrap_or(""),
                "Air-gapped deployment unlocked by imported offline license"
            );
        }
        *state.license_status.write().await = decided;
        // Every API replica listens for committed offline imports. The listener
        // also polls periodically, closing notification-loss and reconnect races.
        let refresh_state = state.clone();
        let refresh_handle = tokio::spawn(async move {
            run_airgap_license_refresh(refresh_state).await;
        });
        state.add_task_handle(refresh_handle).await;
        tracing::info!(
            "Air-gap license refresh started (PostgreSQL NOTIFY + 30s fallback poll)"
        );
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

    // AI usage recorder (NAN-1519) — per-instance writer for the ai_usage_events
    // ledger. Every node makes AI calls and persists its own rows, so this is
    // initialized on all nodes (not leader-only). Enterprise-only: the AI gateway
    // that feeds it lives in nanosiem-enterprise.
    #[cfg(feature = "enterprise")]
    {
        nanosiem_enterprise::melod::usage_recorder::init(state.pool.clone());
        tracing::info!("AI usage recorder started");
    }

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
async fn refresh_airgap_license_status(state: &AppState) {
    let repository = nanosiem_core::LicenseRepository::new(state.pool.clone());
    match repository.get_status().await {
        Ok(persisted) => {
            let decided = airgap_boot_license_status(persisted, chrono::Utc::now());
            *state.license_status.write().await = decided;
        }
        Err(error) => {
            // Keep the last known in-memory status on a transient database
            // failure. The next notification or bounded poll retries.
            tracing::warn!(%error, "Failed to refresh air-gap license status");
        }
    }
}

#[cfg(feature = "enterprise")]
async fn run_airgap_license_refresh(state: AppState) {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
    const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    loop {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&state.pool).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(%error, "Failed to connect air-gap license listener");
                refresh_airgap_license_status(&state).await;
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        if let Err(error) = listener.listen("license_status_changed").await {
            tracing::warn!(%error, "Failed to subscribe air-gap license listener");
            refresh_airgap_license_status(&state).await;
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        // Close the load-before-LISTEN race on startup/reconnect.
        refresh_airgap_license_status(&state).await;
        loop {
            match tokio::time::timeout(POLL_INTERVAL, listener.recv()).await {
                Ok(Ok(_)) | Err(_) => refresh_airgap_license_status(&state).await,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "Air-gap license listener disconnected");
                    break;
                }
            }
        }
    }
}

/// Decide the boot license status for an **air-gapped** deployment (NAN-1222).
///
/// Air-gap installs (`AIRGAP_MODE` on, no `LICENSE_URL`) must FAIL CLOSED: the
/// only way they may run is with a valid, signed, non-expired *offline* license
/// imported via `POST /api/airgap/license/import`. That import path persists a
/// `license_status` row with `offline = TRUE` and a hard `expires_at`.
///
/// `LicenseRepository::get_status()` returns `LicenseStatus::default()`
/// (`offline = false`, `expires_at = None`, `state = Active`) when **no row**
/// exists — i.e. a fresh install is indistinguishable from a "real Active" by
/// `state` alone. We therefore gate on the `offline` marker (only the import
/// handler ever sets it) plus read-time expiry via `effective(now)`:
///
///   - `offline == true` AND `effective(now).state == Active` -> keep that
///     status (the import is genuine and not yet expired).
///   - anything else (no row / `offline == false` / expired) -> `Locked`.
///
/// Pure function (no I/O) so it is unit-testable; `main` feeds it the persisted
/// row and `Utc::now()`.
#[cfg(feature = "enterprise")]
fn airgap_boot_license_status(
    persisted: nanosiem_core::license::LicenseStatus,
    now: chrono::DateTime<chrono::Utc>,
) -> nanosiem_core::license::LicenseStatus {
    use nanosiem_core::license::{LicenseState, LicenseStatus};

    let effective = persisted.effective(now);
    if persisted.offline && effective.state == LicenseState::Active {
        // Genuine, non-expired operator-imported offline license.
        effective
    } else {
        LicenseStatus {
            state: LicenseState::Locked,
            valid: false,
            locked_reason: Some(
                "No license imported — this air-gapped deployment requires a signed offline license."
                    .to_string(),
            ),
            // Preserve any tier/expiry we managed to read for diagnostics, but the
            // state above is what license_guard enforces.
            ..persisted
        }
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod airgap_license_tests {
    use super::airgap_boot_license_status;
    use chrono::{Duration, Utc};
    use nanosiem_core::license::{LicenseState, LicenseStatus};

    /// Fresh air-gap install (no row) -> `get_status` returns the default
    /// (`offline = false`, Active). Must FAIL CLOSED to Locked.
    #[test]
    fn fresh_install_no_license_is_locked() {
        let decided = airgap_boot_license_status(LicenseStatus::default(), Utc::now());
        assert_eq!(decided.state, LicenseState::Locked);
        assert!(!decided.valid);
        assert!(decided.locked_reason.is_some());
    }

    /// A non-offline Active row (defensive: should never exist in air-gap, but a
    /// stray online-style row must not unlock an air-gap install).
    #[test]
    fn non_offline_active_row_is_locked() {
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(Utc::now() + Duration::days(30)),
            offline: false,
            ..Default::default()
        };
        let decided = airgap_boot_license_status(status, Utc::now());
        assert_eq!(decided.state, LicenseState::Locked);
    }

    /// A valid, non-expired offline license unlocks the install.
    #[test]
    fn valid_offline_license_unlocks() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            tier: Some("enterprise".to_string()),
            expires_at: Some(now + Duration::days(30)),
            offline: true,
            ..Default::default()
        };
        let decided = airgap_boot_license_status(status, now);
        assert_eq!(decided.state, LicenseState::Active);
        assert!(decided.valid);
        assert_eq!(decided.tier.as_deref(), Some("enterprise"));
    }

    /// An expired offline license fails closed (read-time self-expiry).
    #[test]
    fn expired_offline_license_is_locked() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(now - Duration::hours(1)),
            offline: true,
            ..Default::default()
        };
        let decided = airgap_boot_license_status(status, now);
        assert_eq!(decided.state, LicenseState::Locked);
        assert!(!decided.valid);
    }
}
