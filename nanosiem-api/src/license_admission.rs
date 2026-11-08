// SPDX-License-Identifier: LicenseRef-NanoSIEM-Enterprise

//! Cached offline-licence admission shared by HTTP routes and workers.
//!
//! Only the API's 30-second authority refresher performs durable C05
//! observations. Request handlers and background-worker startup consume this
//! in-memory snapshot; jobs may populate it through the read-only inspector.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use nanosiem_core::license::{LicenseState, LicenseStatus};
use nanosiem_enterprise::sovereign_license::{
    EntitlementError, LegacyUpgradeGrace, LicenseStateView,
};

use crate::state::AppState;

const LEGACY_NOTICE: &str =
    "Legacy offline licence accepted temporarily after upgrade. Import a C05 licence before the upgrade grace ends.";

#[derive(Debug, Clone)]
pub enum OfflineLicenseSnapshot {
    /// Hosted licensing or a non-air-gap deployment: component checks do not
    /// apply here.
    Bypass,
    C05(LicenseStateView),
    LegacyGrace(LegacyUpgradeGrace),
    Unavailable(String),
}

impl Default for OfflineLicenseSnapshot {
    fn default() -> Self {
        Self::Bypass
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
            Self::Bypass => LicenseStatus::default(),
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
            },
            Self::Unavailable(reason) => LicenseStatus {
                state: LicenseState::Locked,
                valid: false,
                locked_reason: Some(reason.clone()),
                offline: true,
                ..LicenseStatus::default()
            },
        }
    }

    pub fn notice(&self) -> Option<&'static str> {
        matches!(self, Self::LegacyGrace(_)).then_some(LEGACY_NOTICE)
    }

    fn signed_components(&self) -> Option<BTreeSet<&str>> {
        match self {
            Self::C05(view) => Some(view.components.iter().map(String::as_str).collect()),
            _ => None,
        }
    }

    pub fn allows_component(&self, component: &str) -> bool {
        match self {
            Self::Bypass | Self::LegacyGrace(_) => true,
            Self::C05(_) => self
                .signed_components()
                .is_some_and(|components| components.contains(component)),
            Self::Unavailable(_) => false,
        }
    }

    pub fn allows_worker(&self, worker: WorkerCapability) -> bool {
        let Some(component) = component_for_worker(worker) else {
            return false;
        };
        self.allows_component(component)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCapability {
    Soar,
    Risk,
    Melod,
    Pivt,
    Ingest,
}

/// One authoritative mapping for signed component admission. Routes and
/// workers must be named here; worker capabilities absent from this table fail
/// closed. More-specific route prefixes precede their parent prefix.
#[derive(Debug)]
pub struct ComponentRule {
    pub component: &'static str,
    pub route_prefixes: &'static [&'static str],
    pub workers: &'static [WorkerCapability],
}

pub const COMPONENT_RULES: &[ComponentRule] = &[
    ComponentRule {
        component: "ai_tuning",
        route_prefixes: &[
            "/api/melod/detection/tune",
            "/api/melod/settings/ai-tuning",
            "/api/tuning",
        ],
        workers: &[WorkerCapability::Pivt],
    },
    ComponentRule {
        component: "soar",
        route_prefixes: &["/api/soar"],
        workers: &[WorkerCapability::Soar],
    },
    ComponentRule {
        component: "risk",
        route_prefixes: &["/api/risk", "/api/entities", "/api/settings/risk"],
        workers: &[WorkerCapability::Risk],
    },
    ComponentRule {
        component: "melod",
        route_prefixes: &["/api/melod", "/api/settings/ai"],
        workers: &[WorkerCapability::Melod],
    },
    ComponentRule {
        component: "ingest",
        route_prefixes: &[
            "/api/internal/otlp-auth",
            "/api/internal/vector-config",
            "/api/ingest-tokens",
            "/api/connector-specs",
            "/api/connector-feeds",
            "/api/log-sources",
            "/api/source-configurations",
            "/api/integrations",
        ],
        workers: &[WorkerCapability::Ingest],
    },
];

pub fn required_component_for_route(path: &str) -> Option<&'static str> {
    COMPONENT_RULES.iter().find_map(|rule| {
        rule.route_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
            .then_some(rule.component)
    })
}

pub fn component_for_worker(worker: WorkerCapability) -> Option<&'static str> {
    COMPONENT_RULES
        .iter()
        .find(|rule| rule.workers.contains(&worker))
        .map(|rule| rule.component)
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
    Ok(snapshot)
}

pub fn unavailable_snapshot(error: &EntitlementError) -> OfflineLicenseSnapshot {
    OfflineLicenseSnapshot::Unavailable(error.public_reason().into())
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

    #[test]
    fn omitting_each_mapped_component_denies_its_routes_and_workers() {
        let all: BTreeSet<&str> = COMPONENT_RULES.iter().map(|rule| rule.component).collect();
        for rule in COMPONENT_RULES {
            let snapshot = c05_with(all.iter().copied().filter(|name| *name != rule.component));
            for path in rule.route_prefixes {
                assert_eq!(required_component_for_route(path), Some(rule.component));
                assert!(
                    !snapshot.allows_component(rule.component),
                    "{path} was admitted"
                );
            }
            for worker in rule.workers {
                assert!(!snapshot.allows_worker(*worker), "{worker:?} was admitted");
            }
        }
    }

    #[test]
    fn every_worker_capability_is_mapped() {
        for worker in [
            WorkerCapability::Soar,
            WorkerCapability::Risk,
            WorkerCapability::Melod,
            WorkerCapability::Pivt,
            WorkerCapability::Ingest,
        ] {
            assert!(
                component_for_worker(worker).is_some(),
                "{worker:?} is unmapped"
            );
        }
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
}
