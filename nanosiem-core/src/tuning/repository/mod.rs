// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tuning Repository
//!
//! Provides database operations for tuning proposals and audit logs, maintaining
//! a comprehensive audit trail of all auto-tuning activities including proposals,
//! tests, deployments, and reverts.

mod application;
mod logs;
mod proposals;
mod test_results;
#[cfg(test)]
mod tests;

use sqlx::PgPool;

pub use application::{
    AtomicProposalApplyError, AtomicProposalApplyRequest, AtomicProposalApplyResult,
    ProposalRuleMutation,
};
pub use proposals::{
    FrozenPrOperation, PrApprovalProvenance, PrDestinationPayload, PrOperationCheckpoint,
    PrOperationClaim, PrOperationError, PrOperationPhase,
};

// Submodules add impl blocks to TuningRepository; no additional public types to re-export.

/// Summary of a prior tuning proposal for the feedback loop.
///
/// Injected into tuning agent prompts so the AI can learn from
/// previous accepted/rejected proposals.
#[derive(Debug, Clone)]
pub struct ProposalHistorySummary {
    pub status: String,
    pub rationale: String,
    pub confidence_score: f64,
    pub proposed_query: String,
    pub reviewer_notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Repository for tuning operations (proposals and logs)
pub struct TuningRepository {
    pub(crate) pool: PgPool,
}

impl TuningRepository {
    /// Create a new tuning repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
