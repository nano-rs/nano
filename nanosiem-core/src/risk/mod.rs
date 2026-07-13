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
//!
//! `clickhouse_sql` is the shared builder for the decayed accumulated-risk
//! ClickHouse SQL (NAN-1803). It lives in core — not enterprise — so the nPL
//! `dataset=risk` generator (NAN-1798 P2) can compose the same statement the
//! enterprise `RiskRepository` executes.

//! `config_provider` resolves the decay factors + cleared boundaries the
//! `dataset=risk` base source inlines, cached per the design's 60s window
//! (NAN-1798 P2) — the same values the enterprise repository binds.

pub mod clickhouse_sql;
pub mod config_provider;
pub mod types;

pub use types::*;
