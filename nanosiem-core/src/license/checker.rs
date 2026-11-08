// SPDX-License-Identifier: AGPL-3.0-or-later

//! License checker — periodic GET to nano-main for license status
//!
//! Implements the state machine: active → grace_period → locked → active
//! Caches status in PostgreSQL to survive restarts and avoid flapping.

use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

use super::repository::LicenseRepository;
use super::types::{LicenseResponse, LicenseState, LicenseStatus};

/// Maximum time without a successful license check before auto-locking.
/// Prevents the "block the license server DNS" bypass attack.
/// 14 days = enough to survive extended outages, short enough to enforce.
const STALE_LICENSE_DAYS: i64 = 14;

/// Configuration for the license checker
#[derive(Debug, Clone)]
pub struct LicenseCheckerConfig {
    /// License status endpoint URL
    /// e.g. https://api.nano.rs/api/license/status
    /// Legacy heartbeat URLs are auto-converted.
    pub license_url: String,
    pub token: String,
    pub deployment_id: String,
    pub interval_secs: u64,
}

impl LicenseCheckerConfig {
    /// Create config from a license URL (or legacy heartbeat URL).
    /// If the URL contains "/heartbeat", it's automatically converted to "/license/status".
    pub fn from_license_url(
        url: &str,
        token: String,
        deployment_id: String,
        interval_secs: u64,
    ) -> Self {
        let license_url = url
            .trim_end_matches('/')
            .replace("/heartbeat", "/license/status");
        Self {
            license_url,
            token,
            deployment_id,
            interval_secs,
        }
    }
}

/// Periodically checks license status with nano-main and manages the state machine.
pub struct LicenseChecker {
    config: LicenseCheckerConfig,
    http_client: reqwest::Client,
    repo: LicenseRepository,
    license_status: Arc<RwLock<LicenseStatus>>,
}

impl LicenseChecker {
    pub fn new(
        config: LicenseCheckerConfig,
        pool: sqlx::PgPool,
        license_status: Arc<RwLock<LicenseStatus>>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            http_client,
            repo: LicenseRepository::new(pool),
            license_status,
        }
    }

    /// Load cached license status from Postgres on startup.
    /// Call this before starting the periodic loop.
    /// Also checks staleness to prevent restart-after-long-downtime bypass.
    pub async fn load_cached_status(&self) {
        match self.repo.get_status().await {
            Ok(cached) => {
                tracing::info!(
                    state = %cached.state,
                    valid = cached.valid,
                    last_checked = ?cached.last_checked_at,
                    "Loaded cached license status from database"
                );
                let mut status = self.license_status.write().await;
                *status = cached;
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cached license status, defaulting to active");
            }
        }
        // Check staleness immediately on boot
        self.check_staleness().await;
    }

    /// Start the license check loop. Returns a task handle.
    /// Offset by half the interval from heartbeat to spread out requests.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Offset from heartbeat by half the interval
            let offset = Duration::from_secs(self.config.interval_secs / 2);
            tokio::time::sleep(offset).await;

            let mut ticker = interval(Duration::from_secs(self.config.interval_secs));
            ticker.tick().await; // skip immediate tick

            loop {
                ticker.tick().await;
                if let Err(e) = self.check_license().await {
                    tracing::warn!(error = %e, "License check failed (will retry next interval)");
                    // On network failure, keep last known status for transient issues.
                    // But if we haven't reached the license server in STALE_LICENSE_DAYS,
                    // auto-lock to prevent DNS-blocking bypass attacks.
                    self.check_staleness().await;
                }
            }
        })
    }

    /// If the license server hasn't been reached in STALE_LICENSE_DAYS, auto-lock.
    /// Prevents the attack where someone blocks DNS to the license server.
    async fn check_staleness(&self) {
        let mut status = self.license_status.write().await;
        // Only check staleness if we're currently active — don't override locked/grace
        if status.state != LicenseState::Active {
            return;
        }
        // Air-gap installs (offline = TRUE) have no license server to reach, so
        // a stale `last_checked_at` must NOT age them out (NAN-1206 / WS4). Hard
        // expiry (`expires_at`) is still enforced at read time in
        // `LicenseStatus::effective`, independently of staleness.
        if status.offline {
            return;
        }
        if let Some(last_checked) = status.last_checked_at {
            let stale_threshold = chrono::Utc::now() - chrono::Duration::days(STALE_LICENSE_DAYS);
            if last_checked < stale_threshold {
                tracing::error!(
                    days = STALE_LICENSE_DAYS,
                    "License server unreachable for {} days — auto-locking deployment",
                    STALE_LICENSE_DAYS
                );
                status.state = LicenseState::Locked;
                status.valid = false;
                status.locked_reason = Some(format!(
                    "License server unreachable for {} days. Check network connectivity to the license server.",
                    STALE_LICENSE_DAYS
                ));
                if let Err(e) = self.repo.update_status(&status).await {
                    tracing::warn!(error = %e, "Failed to persist stale-lock status");
                }
            }
        }
    }

    async fn check_license(&self) -> Result<(), LicenseCheckError> {
        tracing::debug!(url = %self.config.license_url, "Checking license status");

        let url = format!(
            "{}?deploymentId={}",
            self.config.license_url, self.config.deployment_id
        );
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(&self.config.token)
            .send()
            .await
            .map_err(|e| LicenseCheckError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(LicenseCheckError::ServerError(format!("{status}: {body}")));
        }

        let license_resp: LicenseResponse = resp
            .json()
            .await
            .map_err(|e| LicenseCheckError::ParseError(e.to_string()))?;

        let new_status = self.compute_new_status(&license_resp);

        // Log state transitions
        {
            let current = self.license_status.read().await;
            if current.state != new_status.state {
                tracing::warn!(
                    from = %current.state,
                    to = %new_status.state,
                    valid = new_status.valid,
                    "License state transition"
                );
            }
        }

        // Update in-memory cache
        {
            let mut status = self.license_status.write().await;
            *status = new_status.clone();
        }

        // Persist to Postgres
        if let Err(e) = self.repo.update_status(&new_status).await {
            tracing::warn!(error = %e, "Failed to persist license status to database");
        }

        tracing::debug!(state = %new_status.state, valid = new_status.valid, "License check complete");
        Ok(())
    }

    fn compute_new_status(&self, resp: &LicenseResponse) -> LicenseStatus {
        let now = Utc::now();

        let grace_ends_at = resp
            .grace_ends_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let expires_at = resp
            .expires_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let state = if resp.valid {
            LicenseState::Active
        } else if resp.locked.unwrap_or(false) {
            // Check if we're in grace period
            if let Some(grace_end) = grace_ends_at {
                if now < grace_end {
                    LicenseState::GracePeriod
                } else {
                    LicenseState::Locked
                }
            } else {
                LicenseState::Locked
            }
        } else {
            // Invalid but not explicitly locked — check grace
            if let Some(grace_end) = grace_ends_at {
                if now < grace_end {
                    LicenseState::GracePeriod
                } else {
                    LicenseState::Locked
                }
            } else {
                // No grace info, treat as locked
                LicenseState::Locked
            }
        };

        LicenseStatus {
            state,
            valid: resp.valid,
            tier: resp.tier.clone(),
            locked_reason: resp.locked_reason.clone(),
            grace_ends_at,
            expires_at,
            last_checked_at: Some(now),
            last_heartbeat_at: None, // legacy field, no longer updated
            // Online check-in result: never an air-gap import.
            offline: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseCheckError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Server error: {0}")]
    ServerError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}
