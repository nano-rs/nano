// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk Analytics Types
//!
//! Open core retains only the value types (`EntityRiskSummary`, `RiskFilter`,
//! `RiskTimeWindow`, `RiskLevel`, etc.) — these are referenced by the
//! `CloudRiskProvider` extension trait (`extensions/cloud_risk.rs`) and by the
//! search service (`search/service/cloud_dossier.rs`,
//! `search/service/cloud_overview.rs`).
//!
//! The analytics service (`RiskAnalyticsService` + `RiskRepository`) lives in
//! `nanosiem-enterprise::risk` (lifted in Phase 3.4 of NAN-744). Open-core
//! builds wire `NoopCloudRiskProvider` so cloud overview / dossier surfaces
//! render without risk badges.

pub mod types;

pub use types::*;
