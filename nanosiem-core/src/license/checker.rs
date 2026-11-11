// SPDX-License-Identifier: AGPL-3.0-or-later

//! License checker — periodic GET to nano-main for license status
//!
//! Implements the state machine: active → grace_period → locked → active
//! Caches status in PostgreSQL to survive restarts and avoid flapping.

use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

use super::install_identity::{InstallIdentityRepository, INSTALL_ID_HEADER};
use super::repository::LicenseRepository;
use super::token_rejection::{is_credential_rejection, is_intermediary_refusal, TokenRejection};
use super::types::{LicenseResponse, LicenseState, LicenseStatus};
use crate::TierSettings;

/// Maximum time without a successful license check before auto-locking.
/// Prevents the "block the license server DNS" bypass attack.
/// 14 days = enough to survive extended outages, short enough to enforce.
pub(crate) const STALE_LICENSE_DAYS: i64 = 14;

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
    /// NAN-5249: this install's ID, sent as `X-Nano-Install-Id`.
    install_identity: InstallIdentityRepository,
    /// The install ID once read; it never changes for the life of the database.
    install_id: std::sync::Mutex<Option<String>>,
    tier_settings: TierSettings,
    license_status: Arc<RwLock<LicenseStatus>>,
    /// NAN-5170: optional daily usage report, sent only after a successful
    /// check-in. Enterprise-only; never affects admission.
    #[cfg(feature = "enterprise")]
    usage_reporter: Option<super::usage_report::UsageReporter>,
    /// NAN-5213: with several nano-jobs processes (several app hosts), only
    /// the jobs leader runs the periodic check-in and usage report. The
    /// others keep their admission state current from the PostgreSQL cache.
    leader: Option<(crate::leader::LeaderFence, sqlx::PgPool)>,
    /// When this process last attempted a check-in.
    last_attempt: std::sync::Mutex<Option<std::time::Instant>>,
}

/// How often a non-leading checker (or a leader that is not yet due) reloads
/// the licence status the leader persisted.
const FOLLOWER_REFRESH_SECS: u64 = 300;

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
            repo: LicenseRepository::new(pool.clone()),
            install_identity: InstallIdentityRepository::new(pool.clone()),
            install_id: std::sync::Mutex::new(None),
            tier_settings: TierSettings::new(pool),
            license_status,
            #[cfg(feature = "enterprise")]
            usage_reporter: None,
            leader: None,
            last_attempt: std::sync::Mutex::new(None),
        }
    }

    /// NAN-5213: run the periodic check-in (and its usage report) only while
    /// `fence` holds the jobs leadership. Every process still completes its
    /// own boot check-in in [`Self::initialize`].
    pub fn with_leader_fence(mut self, fence: crate::leader::LeaderFence, pool: sqlx::PgPool) -> Self {
        if fence.is_armed() {
            self.leader = Some((fence, pool));
        }
        self
    }

    fn check_in_due(&self, last_checked_at: Option<DateTime<Utc>>) -> bool {
        let interval = Duration::from_secs(self.config.interval_secs);
        let local_recent = self
            .last_attempt
            .lock()
            .map(|guard| guard.is_some_and(|at| at.elapsed() < interval))
            .unwrap_or(false);
        if local_recent {
            return false;
        }
        // A check-in by another (previous) leader counts too.
        match last_checked_at {
            Some(at) => {
                let age = Utc::now().signed_duration_since(at);
                age.num_seconds() < 0 || age.num_seconds() as u64 >= self.config.interval_secs
            }
            None => true,
        }
    }

    async fn run_check_cycle(&self) {
        if let Err(e) = self.check_license().await {
            if matches!(e, LicenseCheckError::TokenRejected(_)) {
                // NAN-5194: already recorded for SIEM Health and the
                // admin banner; keep retrying under the same bound.
                tracing::error!(error = %e, "Licence token rejected (will retry next interval)");
            } else {
                tracing::warn!(error = %e, "License check failed (will retry next interval)");
            }
            // On network failure, keep last known status for transient issues.
            // But if we haven't reached the license server in STALE_LICENSE_DAYS,
            // auto-lock to prevent DNS-blocking bypass attacks.
            self.check_staleness().await;
        }
    }

    /// NAN-5170: after each successful check-in, report the completed days'
    /// total ingested GB to nano (see [`super::usage_report`]). Only the
    /// jobs singleton opts in. Never call this for an air-gapped install.
    #[cfg(feature = "enterprise")]
    pub fn with_usage_reporting(
        mut self,
        pool: sqlx::PgPool,
        audit: Option<Arc<crate::audit::AuditEmitter>>,
    ) -> Self {
        match super::usage_report::usage_url(&self.config.license_url) {
            Some(url) => {
                self.usage_reporter = Some(super::usage_report::UsageReporter::new(
                    super::usage_report::UsageReportTarget {
                        url,
                        token: self.config.token.clone(),
                        deployment_id: self.config.deployment_id.clone(),
                    },
                    self.http_client.clone(),
                    pool,
                    audit,
                ));
            }
            None => tracing::warn!(
                url = %self.config.license_url,
                "Licence URL is not a /license/status endpoint; usage reporting disabled"
            ),
        }
        self
    }

    /// Load cached license status from Postgres on startup.
    /// Call this before starting the periodic loop.
    /// Also checks staleness to prevent restart-after-long-downtime bypass.
    pub async fn load_cached_status(&self) {
        match self.repo.get_status().await {
            Ok(cached) if !cached.offline && cached.last_checked_at.is_some() => {
                tracing::info!(
                    state = %cached.state,
                    valid = cached.valid,
                    last_checked = ?cached.last_checked_at,
                    "Loaded cached license status from database"
                );
                let mut status = self.license_status.write().await;
                *status = cached.for_online_admission();
            }
            Ok(_) => {
                tracing::warn!(
                    "Cached licence has no successful online observation; failing closed"
                );
                *self.license_status.write().await = LicenseStatus::unavailable(
                    "Online licence has not completed its first successful check.",
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cached licence status; failing closed");
                *self.license_status.write().await =
                    LicenseStatus::unavailable("Cached online licence status is unavailable.");
            }
        }
        // Check staleness immediately on boot
        self.check_staleness().await;
    }

    /// Establish online admission before licensed routes or workers start.
    /// A fresh install remains locked unless this first request succeeds; a
    /// previously observed, non-stale cache remains the bounded outage fallback.
    pub async fn initialize(&self) -> Result<(), LicenseCheckError> {
        self.load_cached_status().await;
        self.check_license().await
    }

    /// Start the license check loop. Returns a task handle.
    /// Offset by half the interval from heartbeat to spread out requests.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        if self.leader.is_some() {
            return self.start_leader_gated();
        }
        tokio::spawn(async move {
            // Offset from heartbeat by half the interval
            let offset = Duration::from_secs(self.config.interval_secs / 2);
            tokio::time::sleep(offset).await;

            let mut ticker = interval(Duration::from_secs(self.config.interval_secs));

            loop {
                ticker.tick().await;
                if let Err(e) = self.check_license().await {
                    if matches!(e, LicenseCheckError::TokenRejected(_)) {
                        // NAN-5194: already recorded for SIEM Health and the
                        // admin banner; keep retrying under the same bound.
                        tracing::error!(error = %e, "Licence token rejected (will retry next interval)");
                    } else {
                        tracing::warn!(error = %e, "License check failed (will retry next interval)");
                    }
                    // On network failure, keep last known status for transient issues.
                    // But if we haven't reached the license server in STALE_LICENSE_DAYS,
                    // auto-lock to prevent DNS-blocking bypass attacks.
                    self.check_staleness().await;
                }
            }
        })
    }

    /// NAN-5213: poll every [`FOLLOWER_REFRESH_SECS`]. The jobs leader checks
    /// in once the interval has passed since the last check-in by any
    /// process; everyone else reloads the status the leader persisted.
    fn start_leader_gated(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let poll = Duration::from_secs(FOLLOWER_REFRESH_SECS.min(self.config.interval_secs.max(1)));
            let mut ticker = interval(poll);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some((fence, pool)) = self.leader.as_ref() else {
                    return;
                };
                let leading = fence.epoch().is_some() && fence.still_leader(pool).await;
                if leading {
                    let persisted = self.repo.get_status().await.ok().and_then(|s| s.last_checked_at);
                    if self.check_in_due(persisted) {
                        self.run_check_cycle().await;
                        continue;
                    }
                }
                self.refresh_cached_status().await;
            }
        })
    }

    /// Reload the persisted online status without the boot-time logging.
    async fn refresh_cached_status(&self) {
        match self.repo.get_status().await {
            Ok(cached) if !cached.offline && cached.last_checked_at.is_some() => {
                *self.license_status.write().await = cached.for_online_admission();
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(%error, "Licence status refresh failed; keeping the current status");
            }
        }
        self.check_staleness().await;
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

    /// Unit tests with no PostgreSQL: seed the cached install ID.
    #[cfg(test)]
    pub(crate) fn with_install_id(self, id: &str) -> Self {
        if let Ok(mut cached) = self.install_id.lock() {
            *cached = Some(id.to_string());
        }
        self
    }

    /// NAN-5249: this install's ID (cached after the first read), or `None`
    /// when it cannot be read (PostgreSQL unavailable).
    pub(crate) async fn install_id(&self) -> Option<String> {
        if let Some(id) = self.install_id.lock().ok().and_then(|g| g.clone()) {
            return Some(id);
        }
        match self.install_identity.get_or_create().await {
            Ok(id) => {
                if let Ok(mut cached) = self.install_id.lock() {
                    *cached = Some(id.clone());
                }
                Some(id)
            }
            Err(error) => {
                tracing::warn!(%error, "Install ID unavailable; checking in without it");
                None
            }
        }
    }

    pub async fn check_license(&self) -> Result<(), LicenseCheckError> {
        tracing::debug!(url = %self.config.license_url, "Checking license status");
        if let Ok(mut last) = self.last_attempt.lock() {
            *last = Some(std::time::Instant::now());
        }
        // NAN-5249: nano-main answers a v2 Self-run check-in without an
        // install ID with "upgrade required" (a lock). An ID that can't be
        // read is a local PostgreSQL problem, so don't ask: fail this attempt
        // like a network error and keep the last known status (bounded by the
        // 14-day staleness lock, as for any outage).
        let Some(install_id) = self.install_id().await else {
            return Err(LicenseCheckError::InstallIdUnavailable);
        };

        // NAN-5114: report the running version so nano-main can show it on
        // the deployment page and decide who still needs a new-version email.
        let url = format!(
            "{}?deploymentId={}&version={}",
            self.config.license_url,
            self.config.deployment_id,
            env!("CARGO_PKG_VERSION")
        );
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(&self.config.token)
            .header(INSTALL_ID_HEADER, install_id.as_str())
            .send()
            .await
            .map_err(|e| LicenseCheckError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if is_intermediary_refusal(status, &body) {
                // NAN-5194: not nano-main's answer, so not a token problem.
                tracing::warn!(
                    %status,
                    "Licence check-in refused by a proxy, WAF or CDN between this install and \
                     the licence server (not a token rejection); check the outbound proxy \
                     configuration. Will retry next interval."
                );
            }
            let error = classify_failure(status, &body);
            if let LicenseCheckError::TokenRejected(http_status) = error {
                // NAN-5194: a refused credential never fixes itself. Record it
                // (SIEM Health finding + admin banner); admission is unchanged
                // and the 14-day bound still applies.
                let rejection = TokenRejection::new(http_status, Utc::now());
                if let Err(e) = self.repo.record_token_rejection(&rejection).await {
                    tracing::warn!(error = %e, "Failed to persist licence token rejection");
                }
            }
            return Err(error);
        }

        let license_resp: LicenseResponse = resp
            .json()
            .await
            .map_err(|e| LicenseCheckError::ParseError(e.to_string()))?;

        // NAN-5194: a parsed 200 proves the token was accepted. Clear the
        // rejection now, before any later admission step can return early.
        if let Err(e) = self.repo.clear_token_rejection().await {
            tracing::warn!(error = %e, "Failed to clear licence token rejection");
        }

        let mut new_status = Self::compute_new_status(&license_resp);

        if new_status.state != LicenseState::Locked {
            if let Some(tier) = new_status.tier.as_deref().map(online_tier_claim) {
                // The legacy online response carries only a tier string. The
                // deployment operator is authoritative local provisioning;
                // never turn a Hosted install into uncapped Self-run while
                // normalizing that old claim.
                let operator = self
                    .tier_settings
                    .get_tier_limits()
                    .await
                    .map_err(|error| LicenseCheckError::Entitlement(error.to_string()))?
                    .entitlement
                    .operator;
                let limits = self
                    .tier_settings
                    .admit_license_tier(tier, operator)
                    .await
                    .map_err(|error| LicenseCheckError::Entitlement(error.to_string()))?;
                new_status.tier = Some(limits.tier.to_string());
            }
        }

        // NAN-5055: an audited deployment grant (e.g. a grandfathered original
        // tenant's AI allowance) is honoured only from this authenticated,
        // successfully parsed check-in, and only while it admits licensed
        // features. Every other outcome (no grant, malformed/unhonoured
        // grant, locked) clears it, so the meter falls back to the
        // provisioned env ceiling and a grant can never escalate.
        let granted_ai_credits = admitted_grant_ai_credits(&new_status, &license_resp);
        self.tier_settings
            .set_granted_ai_credits(granted_ai_credits)
            .await
            .map_err(|error| LicenseCheckError::Entitlement(error.to_string()))?;

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
        // NAN-5114: the "Update available" facts ride on the same successful
        // check-in. A failure here never affects admission.
        if let Err(e) = self
            .repo
            .update_release_notice(license_resp.release.as_ref())
            .await
        {
            tracing::warn!(error = %e, "Failed to persist release notice");
        }

        tracing::debug!(state = %new_status.state, valid = new_status.valid, "License check complete");

        // NAN-5170: the usage report is a separate request made only after the
        // check-in has fully completed; its outcome is recorded, never returned.
        #[cfg(feature = "enterprise")]
        if let Some(reporter) = self.usage_reporter.as_ref() {
            reporter
                .report(Utc::now().date_naive(), Some(install_id.as_str()))
                .await;
        }
        Ok(())
    }

    fn compute_new_status(resp: &LicenseResponse) -> LicenseStatus {
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
            entitlement: resp.entitlement.clone(),
        }
    }
}

/// The online check-in response carries only a legacy `tier` string; nano-main
/// never sends the v2 edition/operator/capacity tuple on the paid/subscription
/// path. Admission is decided by `valid`/`locked`, and in v2 a tier never
/// selects features, so an authenticated admitted response with a tier string
/// this build does not recognize (a future platform plan name, for example)
/// still normalizes to `licensed` instead of failing the whole check. Failing
/// it would leave a fresh install locked and let a cached install age into the
/// 14-day outage lock while its subscription is in good standing.
fn online_tier_claim(tier: &str) -> &str {
    if tier.parse::<crate::OrganizationTier>().is_ok() {
        tier
    } else {
        tracing::warn!(
            tier,
            "Unrecognized online licence tier claim; admitting as licensed"
        );
        "licensed"
    }
}

/// NAN-5055: the AI allowance this check-in grants, or `None`. A grant is
/// honoured only while the observation admits licensed features; a locked
/// response (or one carrying no honoured grant) yields `None`, which clears
/// any previous grant.
fn admitted_grant_ai_credits(status: &LicenseStatus, resp: &LicenseResponse) -> Option<u32> {
    (status.state != LicenseState::Locked)
        .then(|| resp.granted_ai_credits_per_month())
        .flatten()
}

/// NAN-5194: a 401 (or a 403 in nano-main's JSON error shape) means the
/// licence server refused the token (never retried away); anything else
/// non-2xx is transient. The rejection carries no response body.
pub(crate) fn classify_failure(status: reqwest::StatusCode, body: &str) -> LicenseCheckError {
    if is_credential_rejection(status, body) {
        LicenseCheckError::TokenRejected(status.as_u16())
    } else {
        LicenseCheckError::ServerError(format!("{status}: {body}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseCheckError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Server error: {0}")]
    ServerError(String),
    /// nano-main refused the token (401, or a 403 with its JSON error body).
    #[error("Licence token rejected by the licence server (HTTP {0})")]
    TokenRejected(u16),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Entitlement error: {0}")]
    Entitlement(String),
    /// NAN-5249: this install's ID could not be read from PostgreSQL; the
    /// check-in is not attempted and the last known status is kept.
    #[error("Install ID unavailable; check-in skipped")]
    InstallIdUnavailable,
}

#[cfg(test)]
#[path = "checker_tests.rs"]
mod tests;
