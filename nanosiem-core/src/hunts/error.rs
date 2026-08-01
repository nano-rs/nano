// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — hunt errors.
//!
//! [`HuntError::LeaseLost`] is deliberately its own variant rather than a
//! `Forbidden` or a `Conflict`. It is the outcome of the fence reassertion in
//! [`crate::hunts::repository::HuntRepository::commit_sweep_report`], and a
//! runner that receives it must STOP rather than retry: the sweep it was
//! working on has been reassigned, and every result it is holding belongs to a
//! generation of work that no longer exists. Folding it into a generic 409
//! would invite exactly the retry loop the fence exists to end.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum HuntError {
    #[error("Hunt not found: {0}")]
    NotFound(Uuid),

    #[error("Sweep not found: {0}")]
    SweepNotFound(Uuid),

    #[error("Lead not found: {0}")]
    LeadNotFound(Uuid),

    #[error("Runner not found: {0}")]
    RunnerNotFound(Uuid),

    #[error("Rule idea not found: {0}")]
    RuleIdeaNotFound(Uuid),

    /// The sweep is no longer leased to this runner at this fence, or the lease
    /// has expired, or the sweep has already finished. See the module docs.
    #[error("Sweep lease is no longer valid: {0}")]
    LeaseLost(String),

    /// A hunt already has a sweep in flight, or a slot has already been issued.
    /// Distinct from [`Self::LeaseLost`]: the caller may safely try again later.
    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// The caller is authorized but the payload is rejected.
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Log store error: {0}")]
    LogStore(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl HuntError {
    /// HTTP status this error maps to. Mirrored by the `From<HuntError> for
    /// ApiError` impl in `nanosiem-api-lib`; kept here so non-HTTP callers
    /// (jobs, the scheduler) can classify without depending on axum.
    pub fn status_code(&self) -> u16 {
        match self {
            HuntError::NotFound(_)
            | HuntError::SweepNotFound(_)
            | HuntError::LeadNotFound(_)
            | HuntError::RunnerNotFound(_)
            | HuntError::RuleIdeaNotFound(_) => 404,
            HuntError::Validation(_) => 400,
            HuntError::Forbidden(_) => 403,
            // 409 for both: the runner's work is stale (fence) or another
            // sweep is already in flight. Neither is retryable with the same
            // inputs, which is what a 409 tells a client.
            HuntError::LeaseLost(_) | HuntError::Conflict(_) => 409,
            HuntError::Database(_) | HuntError::LogStore(_) | HuntError::Internal(_) => 500,
        }
    }
}
