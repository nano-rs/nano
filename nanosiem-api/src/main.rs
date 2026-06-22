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
        // No phone-home poller: air-gap has no LICENSE_URL to poll. Re-imports
        // update the in-memory RwLock directly (see import_offline_license).
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
