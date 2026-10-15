// SPDX-License-Identifier: AGPL-3.0-or-later
//! Execution-only job interface. Runners do not receive submission, whole-job
//! cancellation, user listing or legacy inline-result mutation capabilities.
use super::job_coordinator_client::HostedClaim;
use super::jobs::{
    DurableJobStoreError, DurableSearchJobClaim, SearchJobProgress, SearchJobResultRef,
    SearchJobStore,
};
use async_trait::async_trait;
use std::time::Duration;

/// Immutable lease handle. Hosted claims retain their authenticated physical
/// namespace binding; callers cannot rebuild one from public job fields.
pub struct RunnerClaim(ClaimBinding);
enum ClaimBinding {
    Legacy(DurableSearchJobClaim),
    Hosted(HostedClaim),
}
impl std::fmt::Debug for RunnerClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerClaim")
            .field("job_id", &self.job_id)
            .finish_non_exhaustive()
    }
}
impl std::ops::Deref for RunnerClaim {
    type Target = DurableSearchJobClaim;
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            ClaimBinding::Legacy(c) => c,
            ClaimBinding::Hosted(c) => c.claim(),
        }
    }
}
impl RunnerClaim {
    pub(super) fn hosted(claim: HostedClaim) -> Self {
        Self(ClaimBinding::Hosted(claim))
    }
    pub(super) fn hosted_claim(&self) -> Result<&HostedClaim, DurableJobStoreError> {
        match &self.0 {
            ClaimBinding::Hosted(c) => Ok(c),
            _ => Err(DurableJobStoreError::ClaimRejected),
        }
    }
    fn legacy(&self) -> Result<&DurableSearchJobClaim, DurableJobStoreError> {
        match &self.0 {
            ClaimBinding::Legacy(c) => Ok(c),
            _ => Err(DurableJobStoreError::ClaimRejected),
        }
    }
}

#[async_trait]
pub trait DurableJobRunnerStore: Send + Sync + std::fmt::Debug {
    async fn reconcile(&self, max_attempts: u32) -> Result<usize, DurableJobStoreError>;
    /// NAN-3559: true when `claim` itself recovers expired leases with the
    /// same transition, policy and per-transaction bound as `reconcile`, so a
    /// runner need not send a separate `reconcile` before every claim. The
    /// hosted coordinator does (its claim transaction runs the reconcile
    /// sweep, and its lease alarm sweeps with no runner polling, NAN-2783);
    /// Redis stores do not, and keep reconcile-then-claim.
    fn claim_recovers_expired_leases(&self) -> bool {
        false
    }
    async fn claim(
        &self,
        owner: &str,
        lease: Duration,
    ) -> Result<Option<RunnerClaim>, DurableJobStoreError>;
    async fn renew(
        &self,
        claim: &RunnerClaim,
        lease: Duration,
    ) -> Result<bool, DurableJobStoreError>;
    async fn progress(
        &self,
        claim: &RunnerClaim,
        progress: &SearchJobProgress,
    ) -> Result<bool, DurableJobStoreError>;
    async fn complete(
        &self,
        claim: &RunnerClaim,
        result: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError>;
    async fn fail(
        &self,
        claim: &RunnerClaim,
        error: &str,
        retryable: bool,
        promote: bool,
        max_attempts: u32,
    ) -> Result<bool, DurableJobStoreError>;
    async fn cancel_claim(&self, claim: &RunnerClaim) -> Result<bool, DurableJobStoreError>;
    /// NAN-2653: return the current attempt to the queue without charging its
    /// failure budget (pin artifacts on a peer pod, or a draining runner).
    /// Stores without a fenced release report `Unsupported`; callers fall back.
    async fn release_claim(&self, _claim: &RunnerClaim) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }
}

/// Existing open-core/dedicated stores retain their implementation and defaults.
#[async_trait]
impl<T: SearchJobStore + ?Sized> DurableJobRunnerStore for T {
    async fn reconcile(&self, max_attempts: u32) -> Result<usize, DurableJobStoreError> {
        self.reconcile_durable_leases(max_attempts).await
    }
    async fn claim(
        &self,
        owner: &str,
        lease: Duration,
    ) -> Result<Option<RunnerClaim>, DurableJobStoreError> {
        Ok(self
            .claim_durable(owner, lease)
            .await?
            .map(|c| RunnerClaim(ClaimBinding::Legacy(c))))
    }
    async fn renew(&self, c: &RunnerClaim, lease: Duration) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.renew_durable_lease(&c.job_id, &c.lease_owner, c.attempt, c.fence, lease)
            .await
    }
    async fn progress(
        &self,
        c: &RunnerClaim,
        p: &SearchJobProgress,
    ) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.update_durable_progress(&c.job_id, &c.lease_owner, c.attempt, c.fence, p)
            .await
    }
    async fn complete(
        &self,
        c: &RunnerClaim,
        r: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.complete_durable(&c.job_id, &c.lease_owner, c.attempt, c.fence, r)
            .await
    }
    async fn fail(
        &self,
        c: &RunnerClaim,
        error: &str,
        retryable: bool,
        promote: bool,
        max_attempts: u32,
    ) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.fail_durable_attempt(
            &c.job_id,
            &c.lease_owner,
            c.attempt,
            c.fence,
            error,
            retryable,
            promote,
            max_attempts,
        )
        .await
    }
    async fn cancel_claim(&self, c: &RunnerClaim) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.cancel_durable_claim(&c.job_id, &c.lease_owner, c.attempt, c.fence)
            .await
    }
    async fn release_claim(&self, c: &RunnerClaim) -> Result<bool, DurableJobStoreError> {
        let c = c.legacy()?;
        self.release_durable_claim(&c.job_id, &c.lease_owner, c.attempt, c.fence)
            .await
    }
}
