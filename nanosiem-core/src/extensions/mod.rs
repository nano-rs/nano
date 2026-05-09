// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extension hooks for plugging enterprise features into the open core.
//!
//! Each hook trait has a `Noop*` default implementation that the open-core
//! build wires in. The enterprise crate (`nanosiem-enterprise`) provides real
//! implementations that get injected at AppState construction time when the
//! `enterprise` Cargo feature is enabled.
//!
//! Trait surface designed in Phase 2.1 (see ~/.claude/plans/buzzing-brewing-crown.md).
//! Method bodies are tightly bounded — only operations the non-enterprise
//! callers actually need. `From` impls between `ExtensionError` and concrete
//! enterprise error types live alongside the trait impls in the enterprise
//! crate, not here.

use thiserror::Error;

pub mod ai_client;
pub mod case_grouping;
pub mod cloud_risk;
pub mod shadow_investigation;
pub mod siem_health_analyzer;
pub mod tuning_proposal_generator;

pub use ai_client::{AiAgentId, AiClient, AiMessage, AiRole, AiStream, NoopAiClient};
pub use case_grouping::{
    AlertCasePermissions, AlertGrouped, CaseGroupingHook, NoopCaseGroupingHook,
};
pub use cloud_risk::{CloudRiskProvider, NoopCloudRiskProvider};
pub use shadow_investigation::{NoopShadowInvestigationHook, ShadowInvestigationHook};
pub use siem_health_analyzer::{NoopSiemHealthAiAnalyzer, SiemHealthAiAnalyzer};
pub use tuning_proposal_generator::TuningProposalGenerator;

/// Errors surfaced by every extension trait. Variants describe failure
/// categories from the caller's perspective, not enterprise implementation
/// detail. The enterprise crate provides `From` impls from concrete service
/// errors (`CaseServiceError`, `RiskAnalyticsError`, `AiProviderError`, etc.)
/// to these variants.
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// The extension is not wired in for this build (open-core noop, or a
    /// feature-gated impl was not compiled in). Callers MAY treat this as a
    /// soft error and degrade gracefully (e.g. siem_health falls back to
    /// rules-based analysis).
    #[error("extension unavailable: {0}")]
    Unavailable(&'static str),

    /// Underlying database operation failed (Postgres or ClickHouse).
    #[error("database error: {0}")]
    Database(String),

    /// AI provider call failed (network, auth, rate limit, malformed response,
    /// timeout).
    #[error("ai provider error: {0}")]
    AiProvider(String),

    /// Settings / config gate prevented the operation (e.g. auto_grouping
    /// disabled, AI credits exhausted, tier limit). Distinct from `Database`
    /// so callers can choose to surface vs. silently skip.
    #[error("gated by settings: {0}")]
    Gated(&'static str),

    /// Catch-all for genuinely unexpected failures. Use sparingly — prefer a
    /// dedicated variant where possible.
    #[error("extension error: {0}")]
    Other(String),
}
