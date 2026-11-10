// SPDX-License-Identifier: LicenseRef-NanoSIEM-Enterprise

//! Cached offline-licence admission shared by HTTP routes and workers.
//!
//! Only the API's 30-second authority refresher performs durable C05
//! observations. Request handlers and background-worker startup consume this
//! in-memory snapshot; jobs may populate it through the read-only inspector.

use chrono::{DateTime, Utc};
use nanosiem_core::license::{LicenseState, LicenseStatus};
use nanosiem_core::{
    auth::ScopeSet,
    extensions::{
        AlertCasePermissions, AlertGrouped, CaseGroupingHook, CloudRiskProvider, ExtensionError,
        ShadowInvestigationHook, SiemHealthAiAnalyzer,
    },
    models::Alert,
    risk::{EntityRiskSummary, RiskFilter, RiskTimeWindow},
    siem_health::{
        analyzer::SuppressedFinding,
        types::{AnalysisResult, CollectedMetrics},
    },
};
use nanosiem_enterprise::sovereign_license::{
    EntitlementError, LegacyUpgradeGrace, LicenseStateView,
};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::state::AppState;

const LEGACY_NOTICE: &str =
    "Legacy offline licence accepted temporarily after upgrade. Import a C05 licence before the upgrade grace ends.";

#[derive(Debug, Clone)]
pub enum OfflineLicenseSnapshot {
    C05(LicenseStateView),
    LegacyGrace(LegacyUpgradeGrace),
    Unavailable(String),
}

impl Default for OfflineLicenseSnapshot {
    fn default() -> Self {
        Self::Unavailable("Licence admission has not been initialized.".into())
    }
}

impl OfflineLicenseSnapshot {
    pub fn c05_view(&self) -> Option<&LicenseStateView> {
        match self {
            Self::C05(view) => Some(view),
            _ => None,
        }
    }

    pub fn legacy_grace(&self) -> Option<&LegacyUpgradeGrace> {
        match self {
            Self::LegacyGrace(grace) => Some(grace),
            _ => None,
        }
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self {
            Self::Unavailable(reason) => Some(reason),
            _ => None,
        }
    }

    pub fn cached_status(&self) -> LicenseStatus {
        match self {
            Self::C05(view) => crate::handlers::license::cache_status(view),
            Self::LegacyGrace(grace) => LicenseStatus {
                state: LicenseState::GracePeriod,
                valid: true,
                tier: grace.tier.clone(),
                locked_reason: None,
                grace_ends_at: Some(grace.grace_until),
                expires_at: Some(grace.grace_until),
                last_checked_at: None,
                last_heartbeat_at: None,
                offline: true,
                entitlement: None,
            },
            Self::Unavailable(reason) => {
                let mut status = LicenseStatus::unavailable(reason.clone());
                status.offline = true;
                status
            }
        }
    }

    pub fn notice(&self) -> Option<&'static str> {
        matches!(self, Self::LegacyGrace(_)).then_some(LEGACY_NOTICE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCapability {
    Cases,
    Soar,
    Melod,
    Pivt,
    Collectors,
    Sso,
}

/// One live decision shared by licensed route, worker and capability gates.
pub fn licensed_features_available(status: &LicenseStatus, now: DateTime<Utc>) -> bool {
    status.effective(now).state != LicenseState::Locked
}

async fn live_admission(status: &tokio::sync::RwLock<LicenseStatus>) -> bool {
    licensed_features_available(&*status.read().await, Utc::now())
}

/// Dynamic adapter for licensed behavior invoked from shared detection workers.
pub struct LicensedCaseGroupingHook {
    inner: Arc<dyn CaseGroupingHook>,
    status: Arc<tokio::sync::RwLock<LicenseStatus>>,
}

impl LicensedCaseGroupingHook {
    pub fn new(
        inner: Arc<dyn CaseGroupingHook>,
        status: Arc<tokio::sync::RwLock<LicenseStatus>>,
    ) -> Self {
        Self { inner, status }
    }
}

#[async_trait::async_trait]
impl CaseGroupingHook for LicensedCaseGroupingHook {
    async fn group_alert(
        &self,
        alert: &Alert,
        rule_name: Option<&str>,
        permissions: Option<AlertCasePermissions>,
    ) -> Result<Option<AlertGrouped>, ExtensionError> {
        if !live_admission(&self.status).await {
            return Ok(None);
        }
        self.inner.group_alert(alert, rule_name, permissions).await
    }
}

/// Dynamic adapter for shadow-investigation calls from shared alert paths.
pub struct LicensedShadowInvestigationHook {
    inner: Arc<dyn ShadowInvestigationHook>,
    status: Arc<tokio::sync::RwLock<LicenseStatus>>,
}

impl LicensedShadowInvestigationHook {
    pub fn new(
        inner: Arc<dyn ShadowInvestigationHook>,
        status: Arc<tokio::sync::RwLock<LicenseStatus>>,
    ) -> Self {
        Self { inner, status }
    }
}

#[async_trait::async_trait]
impl ShadowInvestigationHook for LicensedShadowInvestigationHook {
    async fn on_case_created(
        &self,
        case_id: uuid::Uuid,
        alert: &Alert,
        notebook_id: Option<uuid::Uuid>,
    ) -> Result<(), ExtensionError> {
        if !live_admission(&self.status).await {
            return Ok(());
        }
        self.inner
            .on_case_created(case_id, alert, notebook_id)
            .await
    }

    async fn on_alerts_added(
        &self,
        case_id: uuid::Uuid,
        new_alert_ids: Vec<uuid::Uuid>,
    ) -> Result<(), ExtensionError> {
        if !live_admission(&self.status).await {
            return Ok(());
        }
        self.inner.on_alerts_added(case_id, new_alert_ids).await
    }
}

/// Remove enterprise risk decoration from otherwise-open search surfaces at
/// hard stop without disabling those search surfaces themselves.
pub struct LicensedCloudRiskProvider {
    inner: Arc<dyn CloudRiskProvider>,
    status: Arc<tokio::sync::RwLock<LicenseStatus>>,
}

impl LicensedCloudRiskProvider {
    pub fn new(
        inner: Arc<dyn CloudRiskProvider>,
        status: Arc<tokio::sync::RwLock<LicenseStatus>>,
    ) -> Self {
        Self { inner, status }
    }
}

#[async_trait::async_trait]
impl CloudRiskProvider for LicensedCloudRiskProvider {
    async fn risky_entities(
        &self,
        window: RiskTimeWindow,
        filter: &RiskFilter,
        scope: &ScopeSet,
    ) -> Result<Vec<EntityRiskSummary>, ExtensionError> {
        if !live_admission(&self.status).await {
            return Ok(Vec::new());
        }
        self.inner.risky_entities(window, filter, scope).await
    }

    async fn risk_for_entities(
        &self,
        entities: &[String],
        scope: &ScopeSet,
    ) -> Result<Option<EntityRiskSummary>, ExtensionError> {
        if !live_admission(&self.status).await {
            return Ok(None);
        }
        self.inner.risk_for_entities(entities, scope).await
    }
}

/// Keep core SIEM-health checks running while replacing their licensed AI
/// analysis with the existing deterministic fallback at hard stop.
pub struct LicensedSiemHealthAiAnalyzer {
    inner: Arc<dyn SiemHealthAiAnalyzer>,
    status: Arc<tokio::sync::RwLock<LicenseStatus>>,
}

impl LicensedSiemHealthAiAnalyzer {
    pub fn new(
        inner: Arc<dyn SiemHealthAiAnalyzer>,
        status: Arc<tokio::sync::RwLock<LicenseStatus>>,
    ) -> Self {
        Self { inner, status }
    }
}

#[async_trait::async_trait]
impl SiemHealthAiAnalyzer for LicensedSiemHealthAiAnalyzer {
    async fn analyze_with_ai(
        &self,
        metrics: &CollectedMetrics,
        suppressions: &[SuppressedFinding],
    ) -> Result<AnalysisResult, ExtensionError> {
        if !live_admission(&self.status).await {
            return Err(ExtensionError::Unavailable(
                "SIEM Health AI is unavailable at the licence hard stop",
            ));
        }
        self.inner.analyze_with_ai(metrics, suppressions).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineAuthoritySource {
    C05,
    LegacyGrace,
    Missing,
}

fn offline_authority_source(has_c05: bool, has_legacy_grace: bool) -> OfflineAuthoritySource {
    if has_c05 {
        OfflineAuthoritySource::C05
    } else if has_legacy_grace {
        OfflineAuthoritySource::LegacyGrace
    } else {
        OfflineAuthoritySource::Missing
    }
}

/// Refresh the shared offline snapshot. `durable=true` is reserved for the API
/// authority loop; jobs call the read-only inspector.
pub async fn refresh_offline_snapshot(
    state: &AppState,
    durable: bool,
) -> Result<OfflineLicenseSnapshot, EntitlementError> {
    let has_c05 = state.sovereign_license.has_installed_license().await?;
    let legacy = if has_c05 {
        None
    } else {
        state.sovereign_license.legacy_upgrade_grace().await?
    };
    let snapshot = match offline_authority_source(has_c05, legacy.is_some()) {
        OfflineAuthoritySource::C05 => {
            let view = if durable {
                state.sovereign_license.status().await?
            } else {
                state.sovereign_license.inspect().await?
            };
            OfflineLicenseSnapshot::C05(view)
        }
        OfflineAuthoritySource::LegacyGrace => {
            OfflineLicenseSnapshot::LegacyGrace(legacy.expect("source checked legacy presence"))
        }
        OfflineAuthoritySource::Missing => {
            // `status` on missing state is read-only and supplies the
            // installation identity needed by the import UI.
            OfflineLicenseSnapshot::C05(state.sovereign_license.status().await?)
        }
    };

    *state.license_status.write().await = snapshot.cached_status();
    *state.offline_license_snapshot.write().await = snapshot.clone();
    LAST_GOOD_REFRESH_UNIX.store(Utc::now().timestamp(), Ordering::SeqCst);
    Ok(snapshot)
}

pub fn unavailable_snapshot(error: &EntitlementError) -> OfflineLicenseSnapshot {
    OfflineLicenseSnapshot::Unavailable(error.public_reason().into())
}

/// NAN-5214: how long a good snapshot survives licence-storage errors.
///
/// A PostgreSQL primary switch makes every query fail for seconds. Failing
/// closed on the first error used to lock licensed routes and abort SOAR,
/// cases and collector workers for a blip. Only `Storage` errors qualify: a
/// refusal (revoked, expired, foreign binding, rollback) still locks at once.
pub const STORAGE_ERROR_GRACE_SECS: i64 = 300;

static LAST_GOOD_REFRESH_UNIX: AtomicI64 = AtomicI64::new(0);

/// Whether a refresh failure may keep the current snapshot (pure, for tests).
pub fn keeps_snapshot_through(
    error: &EntitlementError,
    current: &OfflineLicenseSnapshot,
    last_good_unix: i64,
    now_unix: i64,
) -> bool {
    matches!(error, EntitlementError::Storage(_))
        && !matches!(current, OfflineLicenseSnapshot::Unavailable(_))
        && last_good_unix > 0
        && now_unix.saturating_sub(last_good_unix) <= STORAGE_ERROR_GRACE_SECS
}

/// Apply a failed refresh: keep the last good snapshot through a short
/// storage outage, otherwise fail closed.
pub async fn record_refresh_failure(state: &AppState, error: &EntitlementError) {
    let keep = {
        let current = state.offline_license_snapshot.read().await;
        keeps_snapshot_through(
            error,
            &current,
            LAST_GOOD_REFRESH_UNIX.load(Ordering::SeqCst),
            Utc::now().timestamp(),
        )
    };
    if keep {
        tracing::warn!(%error, "licence storage unavailable; keeping the last good snapshot");
        return;
    }
    tracing::error!(%error, "licence admission unavailable; failing closed");
    let snapshot = unavailable_snapshot(error);
    *state.license_status.write().await = snapshot.cached_status();
    *state.offline_license_snapshot.write().await = snapshot;
}

pub fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c05_with(components: impl IntoIterator<Item = &'static str>) -> OfflineLicenseSnapshot {
        OfflineLicenseSnapshot::C05(LicenseStateView {
            state: "running".into(),
            valid: true,
            installation_id: "install-one".into(),
            organization_id: "org-one".into(),
            installation_fingerprint: "00".repeat(32),
            license_id: Some("licence-one".into()),
            license_type: Some("production".into()),
            capacity_gb_per_day: None,
            revision: Some(1),
            valid_from: None,
            expires_at: None,
            grace_until: None,
            observed_at: None,
            recovery_epoch: 0,
            components: components.into_iter().map(str::to_owned).collect(),
            notice: None,
            refusal: None,
            recovery_required: false,
        })
    }

    // NAN-5214: a PostgreSQL primary switch must not lock the licence.
    #[test]
    fn storage_error_keeps_a_recent_good_snapshot() {
        let good = c05_with(["soar"]);
        let storage = EntitlementError::Storage("connection reset".into());
        assert!(keeps_snapshot_through(&storage, &good, 1_000, 1_000 + STORAGE_ERROR_GRACE_SECS));
        assert!(!keeps_snapshot_through(&storage, &good, 1_000, 1_001 + STORAGE_ERROR_GRACE_SECS));
        assert!(!keeps_snapshot_through(&storage, &good, 0, 10));
        let unavailable = OfflineLicenseSnapshot::Unavailable("down".into());
        assert!(!keeps_snapshot_through(&storage, &unavailable, 1_000, 1_001));
    }

    #[test]
    fn refusals_fail_closed_immediately() {
        let good = c05_with(["soar"]);
        for refusal in [EntitlementError::Revoked, EntitlementError::Expired, EntitlementError::ForeignBinding] {
            assert!(!keeps_snapshot_through(&refusal, &good, 1_000, 1_001));
        }
    }

    #[test]
    fn signed_components_are_provenance_not_v2_feature_selectors() {
        let snapshot = c05_with(["api"]);
        let view = snapshot.c05_view().expect("fixture is C05");
        assert!(view.valid);
        assert_eq!(view.components, ["api"]);
    }

    #[test]
    fn c05_authority_wins_when_legacy_grace_also_exists() {
        assert_eq!(
            offline_authority_source(true, true),
            OfflineAuthoritySource::C05
        );
        assert_eq!(
            offline_authority_source(false, true),
            OfflineAuthoritySource::LegacyGrace
        );
    }

    #[test]
    fn default_admission_is_fail_closed() {
        let snapshot = OfflineLicenseSnapshot::default();
        assert_eq!(snapshot.cached_status().state, LicenseState::Locked);
    }

    #[test]
    fn licensed_features_follow_effective_hard_stop() {
        let now = Utc::now();
        let active = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            locked_reason: None,
            ..LicenseStatus::default()
        };
        assert!(licensed_features_available(&active, now));
        assert!(!licensed_features_available(
            &LicenseStatus::unavailable("expired"),
            now
        ));
    }
}
