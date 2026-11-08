// SPDX-License-Identifier: AGPL-3.0-or-later

//! `CloudRiskProvider` — extension point for risk-based alerting (RBA) data.
//!
//! Used by `search/service/cloud_dossier.rs` and `cloud_overview.rs` so the
//! search service can render risk badges without depending on the analytics
//! crate directly. Phase 2.5 introduced this trait; Phase 3.4 (NAN-744)
//! relocated `RiskAnalyticsService` + `RiskRepository` to
//! `nanosiem-enterprise::risk` with `RiskAnalyticsService` implementing
//! this trait on the enterprise side.
//!
//! Open core does not include the RBA framework or Risk page. The
//! `risk_score()` nPL function and `nanosiem-core/src/detection/risk/`
//! engine stay in core; only the analytics layer (entity risk store,
//! time-windowed summaries, decay configuration, entity reset) lives in
//! enterprise. The value types `EntityRiskSummary`, `RiskFilter`,
//! `RiskTimeWindow`, `RiskLevel` stay in core (`risk::types`) so this
//! trait's signatures compile in both editions.

use async_trait::async_trait;

use crate::auth::ScopeSet;
use crate::extensions::ExtensionError;
use crate::risk::{EntityRiskSummary, RiskFilter, RiskTimeWindow};

#[async_trait]
pub trait CloudRiskProvider: Send + Sync {
    /// Top-N risky entities for a window + filter. Used by cloud_overview
    /// account/principal fan-out. Open-core noop returns an empty vec so the
    /// page renders without risk badges.
    async fn risky_entities(
        &self,
        window: RiskTimeWindow,
        filter: &RiskFilter,
        scope: &ScopeSet,
    ) -> Result<Vec<EntityRiskSummary>, ExtensionError>;

    /// Highest-risk summary across an alias list (e.g. all identity-resolved
    /// values for a single principal). Mirrors today's
    /// `RiskAnalyticsService::get_risk_for_entities`.
    async fn risk_for_entities(
        &self,
        entities: &[String],
        scope: &ScopeSet,
    ) -> Result<Option<EntityRiskSummary>, ExtensionError>;
}

/// No-op provider used by open-core builds. Cloud overview / dossier surfaces
/// elide risk-related sections when this is wired in.
pub struct NoopCloudRiskProvider;

#[async_trait]
impl CloudRiskProvider for NoopCloudRiskProvider {
    async fn risky_entities(
        &self,
        _window: RiskTimeWindow,
        _filter: &RiskFilter,
        _scope: &ScopeSet,
    ) -> Result<Vec<EntityRiskSummary>, ExtensionError> {
        Ok(Vec::new())
    }

    async fn risk_for_entities(
        &self,
        _entities: &[String],
        _scope: &ScopeSet,
    ) -> Result<Option<EntityRiskSummary>, ExtensionError> {
        Ok(None)
    }
}
