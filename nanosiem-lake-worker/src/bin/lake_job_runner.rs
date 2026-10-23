// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable lake-query runner (lean cell-only).
//!
//! The job store (hosted coordinator, or Dragonfly/Redis for trusted-local)
//! owns only job metadata, leases, and fencing tokens. Each claimed attempt
//! runs on the tenant's query[T] over its cell route; query[T] commits the
//! result pages manifest-last to the tenant's object store. NAN-3861 retired
//! the gen1 local executor (a `nanosiem-lake-worker --job-spec` child per
//! attempt over an archived generation pin).

use anyhow::{bail, Context, Result};
use chrono::Utc;
#[cfg(feature = "enterprise")]
use nanosiem_core::auth::{
    compose_viewer_scope, permissions, SourceScopeResolver, TenantMembershipResolver,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_automation_keys::{
    TenantAutomationKeyRevalidationIdentity, TenantAutomationKeyService,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_retention_policy::EnterpriseSharedQueryRetentionAuthority;
#[cfg(feature = "enterprise")]
use nanosiem_core::search::DurableSearchCredentialAuthority;
use nanosiem_core::search::{
    DurableJobSigningKey, DurableJobStoreError,
    DurableQueryResourceClass, DurableResultRetentionProof, DurableSearchJobClaim, RedisJobStore,
    LakeCellRoute, LakeCellRouteSource, SearchJobProgress, SearchJobResultRef, SearchTenantScope,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::tenant_entitlements::{TenantComponent, TenantEntitlementResolver};
use nanosiem_lake_worker::error_log::error_chain;
#[cfg(test)]
use nanosiem_core::search::DurableLakeGenerationPin;
use nanosiem_lake_worker::job::{
    LakeQueryJobRequest, LakeQueryJobSpec, ResourceClass, ResultArtifactRef, JOB_SCHEMA_VERSION,
};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_LEASE_SECONDS: u64 = 30;
const DEFAULT_POLL_MILLIS: u64 = 250;
const DEFAULT_MAX_ATTEMPTS: u32 = 2;
const DEFAULT_MEDIUM_SCAN_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_LARGE_SCAN_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const DEFAULT_EXECUTION_SECONDS: u64 = 3_600;
const STORE_RETRY_MAX: Duration = Duration::from_secs(5);
/// NAN-3520: consecutive empty claims back off from `--poll-millis` up to this
/// bound, so an idle slot polls about once a second instead of four times
/// while a newly queued job still waits at most this long to be claimed.
const EMPTY_CLAIM_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// NAN-2653: in-flight attempts get this long after SIGTERM/SIGINT before the
/// runner kills them and hands their jobs back. Must stay below the reader
/// pod's 60 s terminationGracePeriodSeconds, including DRAIN_EXIT_MARGIN.
const DEFAULT_DRAIN_SECONDS: u64 = 45;
const MAX_DRAIN_SECONDS: u64 = 50;
const DRAIN_EXIT_MARGIN: Duration = Duration::from_secs(5);
const DRAIN_SECONDS_ENV: &str = "NANO_LAKE_RUNNER_DRAIN_SECONDS";
/// NAN-2653: how long one runner keeps handing back a job whose admission-pin
/// artifacts are archived only on a peer reader pod before it concludes the
/// peer is gone for good and fails the job so the caller resubmits.
const DEFAULT_PIN_BOUNCE_SECONDS: u64 = 60;
const PIN_BOUNCE_SECONDS_ENV: &str = "NANO_LAKE_RUNNER_PIN_BOUNCE_SECONDS";
const PIN_BOUNCE_BACKOFF_BASE: Duration = Duration::from_millis(250);
const PIN_BOUNCE_BACKOFF_MAX: Duration = Duration::from_secs(5);
/// NAN-2653: consecutive runner-side (job-scoped, not child) attempt failures
/// with no settled attempt in between before the runner stops claiming and
/// exits non-zero. A sick runner must not burn every queued job's budget.
const MAX_CONSECUTIVE_JOB_FAILURES: u32 = 5;
const PIN_UNAVAILABLE_REASON: &str = "PIN_UNAVAILABLE: the search reader that admitted this durable search was replaced before it could run. Resubmit the search.";
const RUNNER_ATTEMPT_FAILURE_REASON: &str =
    "worker execution failed: the durable runner could not complete this attempt";
const RUNNER_RELEASE_REASON: &str = "worker execution failed: durable runner handed back the attempt";
/// NAN-2653: a child that was running when the drain bound elapsed. Charged
/// as a retryable execution failure (see `settle_claim`), never free.
const RUNNER_DRAIN_INTERRUPTED_REASON: &str =
    "worker execution failed: the reader running this durable search shut down mid-attempt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinBounceDecision {
    /// Hand the job back and stay off the queue for `backoff`.
    Release { backoff: Duration },
    /// This pod has handed the job back for longer than the bound: the pin's
    /// owner is gone. Fail it so the caller resubmits against a current pin.
    Expire { bounced_for: Duration },
}

#[derive(Debug, Clone, Copy)]
struct PinBounce {
    first: Instant,
    last: Instant,
    count: u32,
    /// This pod stays off the job until then (the backoff of the last bounce).
    hold_until: Instant,
}

/// Process-local (shared by all slots) record of jobs this pod handed back.
#[derive(Debug)]
struct PinBounceTracker {
    bound: Duration,
    entries: std::collections::HashMap<String, PinBounce>,
}

impl PinBounceTracker {
    fn new(bound: Duration) -> Self {
        Self {
            bound,
            entries: std::collections::HashMap::new(),
        }
    }

    fn record(&mut self, job_id: &str, now: Instant) -> PinBounceDecision {
        let bound = self.bound;
        // A job not seen for a whole bound ran elsewhere (or was cancelled);
        // a later reappearance starts a fresh window.
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.last) <= bound);
        let entry = self.entries.entry(job_id.to_string()).or_insert(PinBounce {
            first: now,
            last: now,
            count: 0,
            hold_until: now,
        });
        entry.count = entry.count.saturating_add(1);
        entry.last = now;
        let bounced_for = now.saturating_duration_since(entry.first);
        if bounced_for >= bound {
            self.entries.remove(job_id);
            return PinBounceDecision::Expire { bounced_for };
        }
        let exponent = entry.count.saturating_sub(1).min(8);
        let backoff = PIN_BOUNCE_BACKOFF_BASE
            .saturating_mul(1_u32 << exponent)
            .min(PIN_BOUNCE_BACKOFF_MAX);
        entry.hold_until = now + backoff;
        PinBounceDecision::Release { backoff }
    }

    /// Time left in this pod's backoff for a job it just handed back. Any
    /// slot that claims such a job hands it straight back (free: it never
    /// started) and sits out the rest of the backoff, so every slot of the
    /// pod — not only the one that bounced it — stays off the queue head.
    fn hold_remaining(&self, job_id: &str, now: Instant) -> Option<Duration> {
        let entry = self.entries.get(job_id)?;
        let remaining = entry.hold_until.saturating_duration_since(now);
        (!remaining.is_zero()).then_some(remaining)
    }

    fn forget(&mut self, job_id: &str) {
        self.entries.remove(job_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainPhase {
    /// No shutdown signal: claim normally.
    Running,
    /// Signalled: claim nothing new, let in-flight attempts finish.
    Draining { remaining: Duration },
    /// Drain bound elapsed: kill in-flight children and hand their jobs back.
    Expired,
}

fn drain_phase(signalled_at: Option<Instant>, drain: Duration, now: Instant) -> DrainPhase {
    match signalled_at {
        None => DrainPhase::Running,
        Some(at) => {
            let elapsed = now.saturating_duration_since(at);
            if elapsed >= drain {
                DrainPhase::Expired
            } else {
                DrainPhase::Draining {
                    remaining: drain - elapsed,
                }
            }
        }
    }
}

/// Shared runner state: the graceful-drain clock and the pin-bounce ledger.
#[derive(Debug)]
struct RunnerControl {
    drain: Duration,
    signalled: tokio::sync::watch::Sender<Option<Instant>>,
    bounces: std::sync::Mutex<PinBounceTracker>,
    /// Consecutive runner-side job failures across all slots.
    job_failure_streak: std::sync::atomic::AtomicU32,
    /// The circuit breaker tripped: drain, then exit non-zero.
    tripped: std::sync::atomic::AtomicBool,
    /// NAN-4290: general slots holding a claim. A small-lane slot claims
    /// only while one does: an idle general slot takes any queued job (small
    /// ones too) at once, so an idle tenant's small slot sends no request.
    general_busy: std::sync::atomic::AtomicUsize,
    general_busy_changed: tokio::sync::Notify,
}

/// NAN-4290: which queued jobs a runner slot claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotLane {
    /// Any queued job, oldest first.
    General,
    /// Only small-job-lane jobs (`nanosiem_core::search::small_job_lane`),
    /// so a 1 h listing never queues behind a 30 d aggregate.
    Small,
}

/// NAN-4290: how long a small-lane slot sits out after its coordinator
/// refused the `lane` claim field (a coordinator that predates the lane).
const SMALL_LANE_UNSUPPORTED_PARK: Duration = Duration::from_secs(600);

/// Held by a general slot while it holds a claim (see `general_busy`).
struct GeneralBusy<'a>(&'a RunnerControl);

impl Drop for GeneralBusy<'_> {
    fn drop(&mut self) {
        self.0.general_busy.fetch_sub(1, Ordering::SeqCst);
        self.0.general_busy_changed.notify_waiters();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobFailureVerdict {
    KeepServing { streak: u32 },
    Trip { streak: u32 },
}

impl RunnerControl {
    fn new(drain: Duration, pin_bounce_bound: Duration) -> Self {
        Self {
            drain,
            signalled: tokio::sync::watch::Sender::new(None),
            bounces: std::sync::Mutex::new(PinBounceTracker::new(pin_bounce_bound)),
            job_failure_streak: std::sync::atomic::AtomicU32::new(0),
            tripped: std::sync::atomic::AtomicBool::new(false),
            general_busy: std::sync::atomic::AtomicUsize::new(0),
            general_busy_changed: tokio::sync::Notify::new(),
        }
    }

    /// NAN-4290: a general slot took a claim; released when dropped.
    fn general_claim(&self) -> GeneralBusy<'_> {
        self.general_busy.fetch_add(1, Ordering::SeqCst);
        self.general_busy_changed.notify_waiters();
        GeneralBusy(self)
    }

    fn general_busy(&self) -> bool {
        self.general_busy.load(Ordering::SeqCst) > 0
    }

    /// NAN-4290: resolves once a general slot holds a claim, or on shutdown.
    async fn until_general_busy(&self) {
        loop {
            let changed = self.general_busy_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.general_busy() || self.draining() {
                return;
            }
            tokio::select! {
                _ = changed => {}
                _ = self.signalled() => return,
            }
        }
    }

    /// An attempt settled normally: the runner itself is healthy.
    fn record_job_settled(&self) {
        self.job_failure_streak.store(0, Ordering::SeqCst);
    }

    /// A runner-side failure was charged to a job. At the threshold the
    /// breaker trips: claim nothing more, drain in-flight work, exit non-zero
    /// so the pod restarts instead of failing the rest of the queue.
    fn record_job_failure(&self) -> JobFailureVerdict {
        let streak = self
            .job_failure_streak
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if streak >= MAX_CONSECUTIVE_JOB_FAILURES {
            self.tripped.store(true, Ordering::SeqCst);
            self.begin_drain();
            JobFailureVerdict::Trip { streak }
        } else {
            JobFailureVerdict::KeepServing { streak }
        }
    }

    fn tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    fn bounce_hold(&self, job_id: &str) -> Option<Duration> {
        self.bounces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .hold_remaining(job_id, Instant::now())
    }

    fn begin_drain(&self) -> bool {
        self.signalled.send_if_modified(|signalled| {
            if signalled.is_some() {
                return false;
            }
            *signalled = Some(Instant::now());
            true
        })
    }

    fn phase(&self) -> DrainPhase {
        drain_phase(*self.signalled.borrow(), self.drain, Instant::now())
    }

    fn draining(&self) -> bool {
        self.phase() != DrainPhase::Running
    }

    /// Resolves as soon as a shutdown signal has been received.
    async fn signalled(&self) -> Instant {
        let mut receiver = self.signalled.subscribe();
        let signalled = match receiver.wait_for(Option::is_some).await {
            Ok(value) => *value,
            Err(_) => None,
        };
        match signalled {
            Some(at) => at,
            None => std::future::pending().await,
        }
    }

    /// Resolves when the drain bound after the signal has elapsed.
    async fn drain_expired(&self) {
        let at = self.signalled().await;
        tokio::time::sleep_until((at + self.drain).into()).await;
    }

    /// Sleep that a shutdown signal cuts short.
    async fn sleep(&self, duration: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(duration) => {}
            _ = self.signalled() => {}
        }
    }

    fn record_bounce(&self, job_id: &str) -> PinBounceDecision {
        self.bounces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record(job_id, Instant::now())
    }

    fn forget_bounce(&self, job_id: &str) {
        self.bounces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .forget(job_id);
    }
}

/// What happened to one claimed attempt, beyond "it ran to a store verdict".
#[derive(Debug, PartialEq, Eq)]
enum ClaimOutcome {
    /// The store holds this attempt's verdict (completed, failed, cancelled,
    /// or fenced off by a newer attempt). Nothing left to do.
    Finished,
    /// No current cell route for the tenant on this runner; hand the job back.
    PinUnavailable(String),
    /// This pod handed the job back moments ago and is still inside that
    /// bounce's backoff: hand it back again (it never started) and sit out
    /// the remaining hold without recording a new bounce.
    BounceHold(Duration),
    /// Shutdown before the child started: hand it back for free.
    Drained,
    /// Shutdown after the child started: it was killed at the drain bound.
    /// Charged to the job (retryable) so a job whose readers keep getting
    /// terminated cannot retry forever.
    DrainInterrupted,
}

/// How an error that escaped one claimed attempt affects the runner process.
#[derive(Debug, PartialEq, Eq)]
enum ClaimErrorAction {
    /// Metadata store unreachable: the lease expires and the reconciler
    /// requeues. The runner loop retries with backoff.
    StoreUnavailable,
    /// Anything else is scoped to this job: fail it (retryable, bounded by the
    /// execution-failure budget) and keep serving other jobs.
    FailJob,
}

fn classify_claim_error(error: &anyhow::Error) -> ClaimErrorAction {
    if is_store_unavailable(error) {
        ClaimErrorAction::StoreUnavailable
    } else {
        ClaimErrorAction::FailJob
    }
}

/// NAN-2361: durable records whose enqueue-time signature did not verify
/// under this runner's tenant key. Each one has already been marked failed by
/// the store; the runner only counts, logs, and moves on. Exposed for tests
/// and for the periodic warning below.
static SIGNATURE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static CLAIM_REJECTIONS: AtomicU64 = AtomicU64::new(0);

fn is_claim_rejection(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<DurableJobStoreError>(),
            Some(DurableJobStoreError::ClaimRejected)
        )
    })
}

fn is_signature_rejection(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<DurableJobStoreError>(),
            Some(DurableJobStoreError::SignatureRejected(_))
        )
    })
}

fn record_signature_rejection(error: &anyhow::Error) -> u64 {
    let total = SIGNATURE_REJECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    tracing::error!(
        error = %error_chain(&error),
        signature_rejections_total = total,
        "rejected a forged or unsigned durable job record; it was marked failed and will not execute"
    );
    total
}

#[derive(Debug)]
struct Arguments {
    redis_url: String,
    hosted_coordinator_config: Option<PathBuf>,
    /// Read only by the enterprise-shared retention authority.
    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    database_url: Option<String>,
    tenant_id: String,
    tenant_scope: SearchTenantScope,
    /// Worker assignment revision of the tenant's physical job namespace.
    /// Enterprise-shared search enqueues under the assignment-versioned key,
    /// so the runner must claim from the same namespace.
    assignment_revision: Option<u64>,
    worker_id: String,
    /// Lean-lake cell-only runner (`--cell-only`, required since NAN-3861
    /// retired the gen1 local executor): every claim executes on the
    /// tenant's query[T] over its cell route; a claim for a tenant without a
    /// current cell route is handed back, never run locally.
    cell_only: bool,
    /// Explicit single-tenant Redis-fenced cell dispatch; never hosted.
    trusted_local: bool,
    /// NAN-2361: this tenant's derived durable-record signing key. Required
    /// for every enterprise-shared runner; optional (unsigned keyspace) for
    /// dedicated deployments.
    job_signing_key_file: Option<PathBuf>,
    result_root: String,
    lease: Duration,
    poll: Duration,
    max_attempts: u32,
    medium_scan_bytes: u64,
    large_scan_bytes: u64,
    execution_seconds: u64,
    concurrency: usize,
    /// NAN-4290: small-job-lane slots beside the `concurrency` general ones
    /// (hosted coordinator only). Each claims only small jobs, and only while
    /// a general slot is busy.
    small_lane_slots: usize,
    /// NAN-2653: graceful-drain bound after SIGTERM/SIGINT.
    drain: Duration,
    /// NAN-2653: how long this runner hands back a job whose pin is archived
    /// on another pod before failing it for resubmission.
    pin_bounce_bound: Duration,
    once: bool,
}

#[cfg(feature = "enterprise")]
struct SharedAuthorityValidator {
    pool: sqlx::PgPool,
    membership: TenantMembershipResolver,
    entitlements: TenantEntitlementResolver,
    source_scope: SourceScopeResolver,
    #[cfg(feature = "enterprise")]
    automation_keys: TenantAutomationKeyService,
}

#[derive(Debug)]
struct AuthorityUnavailable;

#[cfg(feature = "enterprise")]
impl SharedAuthorityValidator {
    fn new(pool: sqlx::PgPool) -> Self {
        Self {
            membership: TenantMembershipResolver::new(pool.clone()),
            entitlements: TenantEntitlementResolver::new(pool.clone()),
            source_scope: SourceScopeResolver::for_durable_jobs(pool.clone()),
            #[cfg(feature = "enterprise")]
            automation_keys: TenantAutomationKeyService::new(pool.clone()),
            pool,
        }
    }

    async fn is_current(
        &self,
        claim: &DurableSearchJobClaim,
    ) -> Result<bool, AuthorityUnavailable> {
        let Some(authority) = claim.authority.as_ref() else {
            return Ok(false);
        };
        let retention = match EnterpriseSharedQueryRetentionAuthority::load_current(
            &self.pool,
            authority.tenant_id,
        )
        .await
        {
            Ok(value) => value,
            Err(nanosiem_core::enterprise_shared_retention_policy::EnterpriseSharedRetentionSelectionError::Database(_)) => return Err(AuthorityUnavailable),
            Err(_) => return Ok(false),
        };
        let tenant_scope = match retention.search_scope() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if retention.assignment_revision != authority.entitlement_assignment_revision {
            return Ok(false);
        }
        if authority.validate_for(tenant_scope, claim.user_id).is_err() {
            return Ok(false);
        }
        match &authority.credential {
            DurableSearchCredentialAuthority::Session {
                access_jti,
                credential_time_micros,
            } => {
                self.is_current_session(claim, authority, *access_jti, *credential_time_micros)
                    .await
            }
            DurableSearchCredentialAuthority::TenantAutomationKey { .. } => {
                #[cfg(feature = "enterprise")]
                {
                    self.is_current_automation_key(claim, authority).await
                }
                #[cfg(not(feature = "enterprise"))]
                {
                    Ok(false)
                }
            }
        }
    }

    async fn is_current_session(
        &self,
        claim: &DurableSearchJobClaim,
        authority: &nanosiem_core::search::DurableSearchJobAuthority,
        access_jti: Uuid,
        credential_time_micros: i64,
    ) -> Result<bool, AuthorityUnavailable> {
        match nanosiem_core::auth::token::is_persisted_access_token_revoked(
            &self.pool,
            access_jti,
            authority.user_id,
            credential_time_micros,
        )
        .await
        {
            Ok(false) => {}
            Ok(true) => return Ok(false),
            Err(_) => return Err(AuthorityUnavailable),
        }
        let user_active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND status = 'active')",
        )
        .bind(authority.user_id)
        .fetch_one(&self.pool)
        .await;
        if !user_active.map_err(|_| AuthorityUnavailable)? {
            return Ok(false);
        }
        let membership = match self
            .membership
            .resolve_bound_micros(
                authority.user_id,
                authority.tenant_id,
                credential_time_micros,
            )
            .await
        {
            Ok(value) => value,
            Err(nanosiem_core::auth::TenantResolutionError::Unavailable) => {
                return Err(AuthorityUnavailable)
            }
            Err(_) => return Ok(false),
        };
        let current_roles = membership
            .roles
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let stamped_roles = authority
            .roles
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let current_permissions = membership
            .permissions
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let stamped_permissions = authority
            .permissions
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if membership.context.tenant_id != authority.tenant_id
            || current_roles != stamped_roles
            || current_permissions != stamped_permissions
        {
            return Ok(false);
        }
        if membership.authority_revision != authority.membership_authority_revision
            && !self
                .membership
                .session_grants_unchanged_since(
                    authority.tenant_id,
                    authority.user_id,
                    authority.membership_authority_revision,
                )
                .await
                .map_err(|_| AuthorityUnavailable)?
        {
            return Ok(false);
        }
        let entitlement = match self.entitlements.resolve(&membership.context).await {
            Ok(value) => value,
            Err(nanosiem_core::tenant_entitlements::TenantEntitlementError::Unavailable) => {
                return Err(AuthorityUnavailable)
            }
            Err(_) => return Ok(false),
        };
        if entitlement.tenant_id != authority.tenant_id
            || entitlement.assignment_revision != authority.entitlement_assignment_revision
            || entitlement
                .require_component(&membership.context, TenantComponent::Search)
                .is_err()
        {
            return Ok(false);
        }
        let source_scope = match self
            .source_scope
            .resolve_for_tenant(
                authority.tenant_id,
                authority.user_id,
                // The grant-history check above permits unrelated session
                // revocations. Resolve source scope against the freshly
                // validated membership epoch, preserving its strict fence.
                membership.authority_revision,
                authority.entitlement_assignment_revision,
                &membership.roles,
                &membership.permissions,
            )
            .await
        {
            Ok(value) => value,
            Err(_) => return Err(AuthorityUnavailable),
        };
        let effective = compose_viewer_scope(
            &source_scope,
            membership
                .permissions
                .iter()
                .any(|permission| permission == permissions::AUDIT_VIEW),
        );
        Ok(effective.deny_set() == &claim.scope_deny
            && effective.artifact_deny_set() == &claim.scope_artifact_deny)
    }

    #[cfg(feature = "enterprise")]
    async fn is_current_automation_key(
        &self,
        claim: &DurableSearchJobClaim,
        authority: &nanosiem_core::search::DurableSearchJobAuthority,
    ) -> Result<bool, AuthorityUnavailable> {
        let DurableSearchCredentialAuthority::TenantAutomationKey {
            key_id,
            owner_user_id,
            key_revision,
            issued_at_micros,
            expires_at_micros,
            tenant_slug,
        } = &authority.credential
        else {
            return Ok(false);
        };
        let Some(issued_at) = chrono::DateTime::<Utc>::from_timestamp_micros(*issued_at_micros)
        else {
            return Ok(false);
        };
        let expires_at = match expires_at_micros {
            Some(value) => match chrono::DateTime::<Utc>::from_timestamp_micros(*value) {
                Some(value) => Some(value),
                None => return Ok(false),
            },
            None => None,
        };
        let expected = TenantAutomationKeyRevalidationIdentity {
            tenant: nanosiem_core::auth::TrustedTenantContext {
                tenant_id: authority.tenant_id,
                tenant_slug: tenant_slug.clone(),
            },
            key_id: *key_id,
            owner_user_id: *owner_user_id,
            key_revision: *key_revision,
            authority_revision: authority.membership_authority_revision,
            assignment_revision: authority.entitlement_assignment_revision,
            issued_at,
            expires_at,
            permissions: authority.permissions.clone(),
        };
        // The runner connects as a bound `job` lake data-path principal, which
        // holds no UPDATE privilege; revalidation runs inside the SECURITY
        // DEFINER authority (9000129) with the same checks and lock order.
        let current = match self
            .automation_keys
            .revalidate_identity_delegated(&expected)
            .await
        {
            Ok(value) => value,
            Err(nanosiem_core::enterprise_shared_automation_keys::TenantAutomationKeyError::Unavailable) => return Err(AuthorityUnavailable),
            Err(_) => return Ok(false),
        };
        if current.tenant != expected.tenant
            || current.info.id != expected.key_id
            || current.info.user_id != Some(expected.owner_user_id)
            || current.info.permissions != expected.permissions
            || current.owner_user_id != expected.owner_user_id
            || current.key_revision != expected.key_revision
            // Delegated SQL verifies both the immutable issuance epoch and
            // the claim epoch against grant history, then returns current
            // authority for the strict downstream source-scope check.
            || current.authority_revision < expected.authority_revision
            || current.assignment_revision != expected.assignment_revision
            || current.issued_at != expected.issued_at
            || current.expires_at != expected.expires_at
            || authority.roles != ["api_key"]
        {
            return Ok(false);
        }
        let entitlement = match self.entitlements.resolve(&current.tenant).await {
            Ok(value) => value,
            Err(nanosiem_core::tenant_entitlements::TenantEntitlementError::Unavailable) => {
                return Err(AuthorityUnavailable)
            }
            Err(_) => return Ok(false),
        };
        if entitlement.tenant_id != authority.tenant_id
            || entitlement.assignment_revision != authority.entitlement_assignment_revision
            || entitlement
                .require_component(&current.tenant, TenantComponent::Search)
                .is_err()
        {
            return Ok(false);
        }
        let source_scope = match self
            .source_scope
            .resolve_for_tenant_credential(
                authority.tenant_id,
                current.owner_user_id,
                current.info.id,
                current.authority_revision,
                current.assignment_revision,
                &current.info.permissions,
            )
            .await
        {
            Ok(value) => value,
            Err(_) => return Err(AuthorityUnavailable),
        };
        let effective = compose_viewer_scope(
            &source_scope,
            current
                .info
                .permissions
                .iter()
                .any(|permission| permission == permissions::AUDIT_VIEW),
        );
        Ok(effective.deny_set() == &claim.scope_deny
            && effective.artifact_deny_set() == &claim.scope_artifact_deny)
    }
}

#[cfg(not(feature = "enterprise"))]
struct SharedAuthorityValidator;

#[cfg(not(feature = "enterprise"))]
impl SharedAuthorityValidator {
    async fn is_current(
        &self,
        _claim: &DurableSearchJobClaim,
    ) -> Result<bool, AuthorityUnavailable> {
        Ok(false)
    }
}

async fn current_claim_authority(
    validator: Option<&SharedAuthorityValidator>,
    tenant_scope: SearchTenantScope,
    claim: &DurableSearchJobClaim,
) -> Result<bool, AuthorityUnavailable> {
    match tenant_scope {
        SearchTenantScope::Dedicated => Ok(validator.is_none() && claim.authority.is_none()),
        SearchTenantScope::EnterpriseShared(_) => Ok(false),
        SearchTenantScope::EnterpriseSharedRetained { tenant_id, .. } => {
            if claim.tenant_id != Some(tenant_id) {
                return Ok(false);
            }
            match validator {
                Some(validator) => validator.is_current(claim).await,
                None => Ok(false),
            }
        }
    }
}

const USAGE: &str = "usage: lake_job_runner --tenant-id <uuid> --result-root <s3://|file://...> \
[--hosted-coordinator-config <abs path> | --redis-url <url>] [--assignment-revision <n>] \
--cell-only \
[--job-signing-key-file <abs path>] [--concurrency <1-16>] [--small-lane-slots <0-4>] [--lease-seconds <n>] [--poll-millis <n>] \
[--max-attempts <n>] [--execution-seconds <n>] [--drain-seconds <n>] [--once]
  --trusted-local  dedicated UUID tenant, Redis-fenced cell-only execution (no hosted config)
  --iceberg-export  isolated hourly customer export (default OFF; optional --once)
  --cell-only  lean-lake: run every claim on the tenant's query[T] via NANO_LAKE_CELL_ROUTES_FILE +
               NANO_LAKE_CELL_ROUTER_TOKEN_FILE (requires --hosted-coordinator-config)";

/// `--cell-only` dispatches every claim over the cell route, so both route
/// inputs must be configured (a half-configured pair disables cell routing).
fn require_cell_route_env(routes_file: Option<&str>, router_token_file: Option<&str>) -> Result<()> {
    let set = |value: Option<&str>| value.is_some_and(|value| !value.trim().is_empty());
    if !set(routes_file) || !set(router_token_file) {
        bail!(
            "--cell-only requires {} and {}",
            nanosiem_core::search::lake_cell::LAKE_CELL_ROUTES_FILE_ENV,
            nanosiem_core::search::lake_cell::LAKE_CELL_ROUTER_TOKEN_FILE_ENV
        );
    }
    Ok(())
}

/// The process-wide cell route registry. It re-reads the mounted routes file
/// itself (at most every `ROUTES_RELOAD_INTERVAL`), so placement moves are
/// picked up without rebuilding it for every claim.
fn cell_route_source() -> Option<std::sync::Arc<LakeCellRouteSource>> {
    static SOURCE: std::sync::OnceLock<Option<std::sync::Arc<LakeCellRouteSource>>> =
        std::sync::OnceLock::new();
    SOURCE.get_or_init(LakeCellRouteSource::from_env).clone()
}

// Reuse lane A's single-tenant loader; the hosted source intentionally rejects Compose origins.
fn trusted_local_cell_route(arguments: &Arguments) -> Result<std::sync::Arc<LakeCellRoute>> {
    anyhow::ensure!(arguments.trusted_local, "local cell route requires explicit trusted-local mode");
    let route = nanosiem_core::search::lake_cell::dedicated_route_from_env()
        .map_err(anyhow::Error::msg)?.context("trusted-local runner requires its dedicated cell route")?;
    validate_trusted_local_cell_route(arguments, route)
}

fn validate_trusted_local_cell_route(arguments: &Arguments, route: std::sync::Arc<LakeCellRoute>) -> Result<std::sync::Arc<LakeCellRoute>> {
    anyhow::ensure!(route.tenant_id.to_string() == arguments.tenant_id, "trusted-local cell route names another tenant");
    route.validate_query_base().map_err(anyhow::Error::msg)?;
    Ok(route)
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().skip(1).any(|argument| argument == "--help" || argument == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    nanosiem_lake_worker::process_limits::initialize()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // nanosiem_core=warn: coordinator transport/store refusals
                // (operation, status, error code) must reach the pod log.
                .unwrap_or_else(|_| {
                    "lake_job_runner=info,nanosiem_lake_worker=info,nanosiem_core=warn".into()
                }),
        )
        .json()
        .init();
    if std::env::args().skip(1).any(|arg|arg=="--iceberg-export") {
        let mut termination=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        return tokio::select! {
            result=nanosiem_lake_worker::part_ingest::iceberg_export::runner::run_from_env()=>result.map_err(|_|anyhow::anyhow!("customer Iceberg export startup failed")),
            _=termination.recv()=>Ok(()),
            _=tokio::signal::ctrl_c()=>Ok(()),
        };
    }
    #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
    let mut arguments = Arguments::parse(std::env::args().skip(1))?;
    if arguments.trusted_local { trusted_local_cell_route(&arguments)?; }
    if arguments.cell_only {
        require_cell_route_env(
            std::env::var(nanosiem_core::search::lake_cell::LAKE_CELL_ROUTES_FILE_ENV).ok().as_deref(),
            std::env::var(nanosiem_core::search::lake_cell::LAKE_CELL_ROUTER_TOKEN_FILE_ENV).ok().as_deref(),
        )?;
    }
    #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
    let mut entitlement_revision = None;
    let authority_validator = match arguments.tenant_scope {
        SearchTenantScope::Dedicated => None,
        SearchTenantScope::EnterpriseShared(_) => {
            #[cfg(feature = "enterprise")]
            {
                let database_url = arguments
                    .database_url
                    .as_deref()
                    .context("enterprise-shared durable runner requires DATABASE_URL")?;
                let pool = nanosiem_core::db::pooler::connect_lazy(nanosiem_core::db::connection_budget::pool_options(2), database_url)
                    .context("connect durable job authority database")?;
                let tenant_id = arguments
                    .tenant_scope
                    .tenant_id()
                    .context("enterprise-shared durable runner tenant is absent")?;
                let retention =
                    EnterpriseSharedQueryRetentionAuthority::load_current(&pool, tenant_id)
                        .await
                        .context("load current enterprise-shared durable retention policy")?;
                arguments.tenant_scope = retention
                    .search_scope()
                    .context("resolve enterprise-shared durable retention identity")?;
                entitlement_revision = Some(retention.assignment_revision);
                Some(SharedAuthorityValidator::new(pool))
            }
            #[cfg(not(feature = "enterprise"))]
            {
                bail!("enterprise_shared durable runner requires the enterprise build")
            }
        }
        SearchTenantScope::EnterpriseSharedRetained { .. } => {
            bail!("retention scope must be resolved from PostgreSQL, not process arguments")
        }
    };
    let store: Box<dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore> =
        if let Some(path) = arguments.hosted_coordinator_config.as_deref() {
            use nanosiem_core::search::{
                job_coordinator_client::{HostedAssignment, HostedCoordinatorRole},
                job_coordinator_config::HostedCoordinatorDeployment,
            };
            let tenant_id = arguments
                .tenant_scope
                .tenant_id()
                .context("hosted runner requires a shared tenant")?;
            if arguments.result_root
                != format!("s3://nano-shared-r2-{tenant_id}/{tenant_id}/durable-query-result/v1")
            {
                bail!("hosted runner requires the exact tenant-scoped R2 result root");
            }
            let key_path = arguments
                .job_signing_key_file
                .as_deref()
                .context("hosted runner signing key is required")?;
            let signer = DurableJobSigningKey::from_file(key_path, tenant_id)
                .context("load hosted runner signing key")?;
            let config = HostedCoordinatorDeployment::from_file(path)?;
            let client = config
                .connect(
                    arguments.tenant_scope,
                    HostedAssignment {
                        entitlement_revision: entitlement_revision
                            .context("hosted entitlement revision must come from PostgreSQL")?,
                        worker_revision: arguments
                            .assignment_revision
                            .context("hosted worker assignment is required")?,
                    },
                    HostedCoordinatorRole::Runner,
                    arguments.max_attempts,
                    std::sync::Arc::new(signer),
                )
                .await?;
            Box::new(client)
        } else {
            let store = match arguments.tenant_scope {
                SearchTenantScope::Dedicated => RedisJobStore::connect(&arguments.redis_url).await,
                SearchTenantScope::EnterpriseShared(_) => None,
                #[cfg(feature = "enterprise")]
                retained @ SearchTenantScope::EnterpriseSharedRetained { .. } => {
                    match arguments.assignment_revision {
                        Some(revision) => {
                            RedisJobStore::connect_enterprise_shared_retained_assignment(
                                &arguments.redis_url,
                                retained,
                                revision,
                            )
                            .await
                        }
                        None => {
                            RedisJobStore::connect_enterprise_shared_retained(
                                &arguments.redis_url,
                                retained,
                            )
                            .await
                        }
                    }
                }
                #[cfg(not(feature = "enterprise"))]
                SearchTenantScope::EnterpriseSharedRetained { .. } => None,
            }
            .context("connect durable job metadata store")?;
            let store = match arguments.job_signing_key_file.as_deref() {
                Some(path) => {
                    let tenant_id = match arguments.tenant_scope.tenant_id() {
                        Some(tenant_id) => tenant_id,
                        None => Uuid::parse_str(&arguments.tenant_id)
                            .context("dedicated runner signing key requires a UUID tenant id")?,
                    };
                    let key = DurableJobSigningKey::from_file(path, tenant_id)
                        .context("load durable job signing key")?;
                    store
                        .with_job_signing_key(key)
                        .context("bind durable job signing key to the tenant store")?
                }
                None => {
                    if !matches!(arguments.tenant_scope, SearchTenantScope::Dedicated) {
                        bail!(
                    "enterprise-shared durable runner requires --job-signing-key-file or NANO_LAKE_JOB_SIGNING_KEY_FILE"
                );
                    }
                    store
                }
            };

            Box::new(store)
        };

    let slots = if arguments.once {
        1
    } else {
        arguments.concurrency
    };
    // NAN-2653: the runner is PID 1 (`sh -ec exec`), where an unhandled
    // SIGTERM is ignored and the pod is SIGKILLed after its grace period with
    // every in-flight attempt abandoned to lease expiry. Register before the
    // first claim so no signal can arrive unobserved.
    let control = std::sync::Arc::new(RunnerControl::new(
        arguments.drain,
        arguments.pin_bounce_bound,
    ));
    spawn_shutdown_listener(control.clone())?;
    let small_slots = if arguments.once { 0 } else { arguments.small_lane_slots };
    let lanes = std::iter::repeat_n(SlotLane::General, slots).chain(std::iter::repeat_n(SlotLane::Small, small_slots));
    let runners = futures::future::try_join_all(lanes.map(|lane| {
        runner_loop(
            store.as_ref(),
            &arguments,
            authority_validator.as_ref(),
            &control,
            lane,
        )
    }));
    tokio::pin!(runners);
    tokio::select! {
        result = &mut runners => {
            result?;
        }
        _ = async {
            control.drain_expired().await;
            tokio::time::sleep(DRAIN_EXIT_MARGIN).await;
        } => {
            // Handing back an attempt needs one store round trip; if even
            // that hangs, exit before the kubelet's SIGKILL. Dropping the
            // slots kills their children (kill_on_drop) and the reconciler
            // requeues any lease that was not released.
            tracing::warn!(
                drain_seconds = arguments.drain.as_secs(),
                "durable runner drain bound elapsed with work still unwinding; exiting"
            );
        }
    }
    if control.tripped() {
        bail!(
            "durable runner circuit breaker tripped after {MAX_CONSECUTIVE_JOB_FAILURES} consecutive runner-side attempt failures"
        );
    }
    if control.draining() {
        tracing::info!("durable runner drained; exiting");
    }
    Ok(())
}

fn spawn_shutdown_listener(control: std::sync::Arc<RunnerControl>) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate =
            signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        tokio::spawn(async move {
            loop {
                let name = tokio::select! {
                    _ = terminate.recv() => "SIGTERM",
                    _ = interrupt.recv() => "SIGINT",
                };
                if control.begin_drain() {
                    tracing::info!(
                        signal = name,
                        drain_seconds = control.drain.as_secs(),
                        "durable runner draining: no new claims; in-flight attempts finish or are handed back"
                    );
                } else {
                    tracing::info!(signal = name, "durable runner already draining");
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                control.begin_drain();
            }
        });
    }
    Ok(())
}

async fn runner_loop(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    authority_validator: Option<&SharedAuthorityValidator>,
    control: &RunnerControl,
    lane: SlotLane,
) -> Result<()> {
    let mut store_failure_streak = 0_u32;
    tracing::info!(worker_id = %arguments.worker_id, ?lane, "durable runner uses unique attempt-session lease owners");
    let mut pending_claim_owner = None;
    let mut empty_claims = 0_u32;
    loop {
        // NAN-4290: the small lane waits for a busy general slot. A lost
        // claim response is still retried at once with the same owner.
        if lane == SlotLane::Small && pending_claim_owner.is_none() {
            control.until_general_busy().await;
        }
        // NAN-2653: a draining runner claims nothing new.
        if control.draining() {
            return Ok(());
        }
        match run_iteration(
            store,
            arguments,
            authority_validator,
            &mut pending_claim_owner,
            &mut empty_claims,
            control,
            lane,
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => store_failure_streak = 0,
            Err(error) if is_signature_rejection(&error) => {
                // The store already failed the record under our lease; a
                // forged hash must not take the runner down or stall the
                // queue behind it.
                record_signature_rejection(&error);
                store_failure_streak = 0;
                if arguments.once {
                    return Err(error);
                }
            }
            Err(error) if is_claim_rejection(&error) => {
                let total = CLAIM_REJECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    claim_rejections_total = total,
                    "skipping a durable job rejected before execution"
                );
                store_failure_streak = 0;
                if arguments.once {
                    return Err(error);
                }
            }
            Err(error) if !arguments.once && is_store_unavailable(&error) => {
                store_failure_streak = store_failure_streak.saturating_add(1);
                let retry_after = store_retry_delay(store_failure_streak, arguments.poll);
                tracing::warn!(
                    error = %error,
                    consecutive_failures = store_failure_streak,
                    retry_after_ms = retry_after.as_millis(),
                    "durable job metadata is temporarily unavailable; retrying without restarting"
                );
                control.sleep(retry_after).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_iteration(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    authority_validator: Option<&SharedAuthorityValidator>,
    pending_claim_owner: &mut Option<String>,
    empty_claims: &mut u32,
    control: &RunnerControl,
    lane: SlotLane,
) -> Result<bool> {
    // NAN-3559: the hosted coordinator's claim already recovers expired
    // leases (same transition, policy and bound), and its lease alarm sweeps
    // on its own; a separate reconcile per idle poll doubled its request rate
    // (~1.75/s per idle tenant). Redis stores keep reconcile-then-claim.
    if !store.claim_recovers_expired_leases() {
        let reconciled = store.reconcile(arguments.max_attempts).await?;
        if reconciled > 0 {
            tracing::warn!(reconciled, "reconciled expired durable query leases");
        }
    }
    // A lost claim response retries with the same attempt-session owner. A
    // successful response starts a new session on the next iteration; stable
    // hostnames must never deduplicate unrelated concurrent attempts.
    let owner = pending_claim_owner.get_or_insert_with(|| Uuid::now_v7().to_string());
    let claim_started = Instant::now();
    let claimed = match lane {
        SlotLane::General => store.claim(owner, arguments.lease).await,
        SlotLane::Small => store.claim_small(owner, arguments.lease).await,
    };
    if lane == SlotLane::Small && small_lane_refused(&claimed) {
        // A coordinator that predates the lane: the general slot still runs
        // every job, as before NAN-4290.
        *pending_claim_owner = None;
        tracing::warn!(
            park_seconds = SMALL_LANE_UNSUPPORTED_PARK.as_secs(),
            "job coordinator refused the small-lane claim; the small slot sits out"
        );
        control.sleep(SMALL_LANE_UNSUPPORTED_PARK).await;
        return Ok(false);
    }
    if claimed.is_ok() || !matches!(&claimed, Err(DurableJobStoreError::Unavailable(_))) {
        *pending_claim_owner = None;
    }
    let claim = claimed?;
    match claim {
        Some(claim) => {
            *empty_claims = 0;
            let _busy = (lane == SlotLane::General).then(|| control.general_claim());
            nanosiem_lake_worker::job_capacity::JobPhaseTimings {
                claim_ms: Some(claim_started.elapsed().as_millis() as u64),
                ..Default::default()
            }
            .log(&claim.job_id);
            // A foreign-tenant claim means this runner is bound to the wrong
            // namespace: a process-level configuration failure.
            claim.verify_worker_tenant(arguments.tenant_scope)?;
            let outcome = run_claim(store, arguments, &claim, authority_validator, control).await;
            settle_claim(store, arguments, &claim, outcome, control).await?;
        }
        None if arguments.once => return Ok(true),
        None => {
            *empty_claims = empty_claims.saturating_add(1);
            control.sleep(empty_claim_delay(*empty_claims, arguments.poll)).await;
        }
    }
    Ok(arguments.once)
}

/// NAN-4290: the coordinator refused the small-lane claim itself: it
/// predates the `lane` field (`invalid_command`) or the store has no lanes.
fn small_lane_refused(
    claimed: &std::result::Result<Option<nanosiem_core::search::job_runner_store::RunnerClaim>, DurableJobStoreError>,
) -> bool {
    match claimed {
        Err(DurableJobStoreError::Unsupported) => true,
        Err(DurableJobStoreError::Unavailable(message)) => {
            message.contains("code invalid_command") || message.contains("code invalid_lane")
        }
        _ => false,
    }
}

/// NAN-2653: turn one attempt's outcome into a store verdict without letting
/// a job-scoped failure take down the runner (and every other slot's
/// in-flight attempt with it). Only store-unavailability, claim/signature
/// rejections, a tripped job-failure circuit breaker, and `--once` propagate.
async fn settle_claim(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    outcome: Result<ClaimOutcome>,
    control: &RunnerControl,
) -> Result<()> {
    let error = match outcome {
        Ok(ClaimOutcome::Finished) => {
            control.forget_bounce(&claim.job_id);
            control.record_job_settled();
            return Ok(());
        }
        Ok(ClaimOutcome::Drained) => {
            // The child never started: free hand-back.
            let released = hand_back_claim(store, arguments, claim).await?;
            tracing::info!(
                job_id = %claim.job_id,
                attempt = claim.attempt,
                fence = claim.fence,
                released,
                "draining runner handed back a durable attempt that had not started"
            );
            return Ok(());
        }
        Ok(ClaimOutcome::DrainInterrupted) => {
            // The child ran and was killed at the drain bound. Charge it as a
            // retryable execution failure: it is requeued at once for the
            // surviving reader (lease expiry would add up to a whole lease
            // plus a reconcile tick), yet bounded by the same max_attempts
            // budget that lease recovery would have charged.
            let requeued = verdict_or_log(
                store
                    .fail(
                        claim,
                        RUNNER_DRAIN_INTERRUPTED_REASON,
                        true,
                        false,
                        arguments.max_attempts,
                    )
                    .await,
                claim,
                "record drain-interrupted durable attempt",
            )?;
            tracing::warn!(
                job_id = %claim.job_id,
                attempt = claim.attempt,
                fence = claim.fence,
                fence_current = requeued,
                "drain bound elapsed mid-attempt; charged the attempt and requeued it for another reader"
            );
            return Ok(());
        }
        Ok(ClaimOutcome::BounceHold(remaining)) => {
            let released = hand_back_claim(store, arguments, claim).await?;
            tracing::debug!(
                job_id = %claim.job_id,
                released,
                hold_ms = remaining.as_millis() as u64,
                "pod is still backing off a durable job it handed back; skipping it"
            );
            control.sleep(remaining).await;
            return Ok(());
        }
        Ok(ClaimOutcome::PinUnavailable(reason)) => {
            return bounce_pin_unavailable(store, arguments, claim, &reason, control).await;
        }
        Err(error) => error,
    };
    if is_signature_rejection(&error) || is_claim_rejection(&error) {
        return Err(error);
    }
    // NAN-3911: too large to ever run. Fail it once, non-retryable, with the
    // actionable category. It is the job's shape, not a sick runner, so it
    // does not count toward the consecutive-failure circuit breaker.
    if let Some(category) = query_too_large(&error) {
        // NAN-4290: a small-lane job ran at one interactive lane's memory;
        // the general lane has the large class's. Retry it once there.
        if category == nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE && small_lane_job(claim) {
            tracing::warn!(
                job_id = %claim.job_id,
                attempt = claim.attempt,
                fence = claim.fence,
                error = %error_chain(&error),
                "small-lane durable search exceeded its memory; requeued once as large for the general lane"
            );
            verdict_or_log(
                store.fail(claim, category, true, true, arguments.max_attempts).await,
                claim,
                "promote small-lane durable attempt",
            )?;
            control.record_job_settled();
            return Ok(());
        }
        tracing::warn!(
            job_id = %claim.job_id,
            attempt = claim.attempt,
            fence = claim.fence,
            error = %error_chain(&error),
            "durable search is too large to run; failing it without retry"
        );
        verdict_or_log(
            store.fail(claim, category, false, false, arguments.max_attempts).await,
            claim,
            "record query-too-large durable attempt",
        )?;
        control.record_job_settled();
        return Ok(());
    }
    match classify_claim_error(&error) {
        ClaimErrorAction::StoreUnavailable => Err(error),
        ClaimErrorAction::FailJob => {
            tracing::error!(
                job_id = %claim.job_id,
                attempt = claim.attempt,
                fence = claim.fence,
                error = %error_chain(&error),
                "durable attempt failed inside the runner; failing this job only"
            );
            verdict_or_log(
                store
                    .fail(
                        claim,
                        RUNNER_ATTEMPT_FAILURE_REASON,
                        true,
                        false,
                        arguments.max_attempts,
                    )
                    .await,
                claim,
                "record runner-side durable attempt failure",
            )?;
            if arguments.once {
                return Err(error);
            }
            if let JobFailureVerdict::Trip { streak } = control.record_job_failure() {
                // The breaker has begun a drain: every slot stops claiming,
                // in-flight attempts finish or are charged at the bound, and
                // `main` exits non-zero so the pod restarts.
                tracing::error!(
                    consecutive_failures = streak,
                    last_error = %error_chain(&error),
                    "durable runner failed consecutive attempts itself; circuit breaker tripped, draining to exit"
                );
            }
            Ok(())
        }
    }
}

/// A store verdict on a hand-back or failure path. Only an unreachable store
/// propagates (the runner loop backs off; lease expiry covers the job). Any
/// other refusal (invalid metadata, a rejected or unsupported claim) is
/// scoped to this one attempt: log it and keep serving.
fn verdict_or_log(
    result: std::result::Result<bool, DurableJobStoreError>,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    what: &'static str,
) -> Result<bool> {
    match result {
        Ok(changed) => Ok(changed),
        Err(error @ DurableJobStoreError::Unavailable(_)) => {
            Err(anyhow::Error::from(error).context(what))
        }
        Err(error) => {
            tracing::warn!(
                job_id = %claim.job_id,
                attempt = claim.attempt,
                fence = claim.fence,
                error = %error,
                "{what} was refused; lease recovery will requeue the job"
            );
            Ok(false)
        }
    }
}

/// Fenced hand-back that does not charge the job's failure budget. Stores
/// without a release operation fall back to a retryable failure, which is
/// still faster than waiting out the lease.
async fn hand_back_claim(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
) -> Result<bool> {
    let result = match store.release_claim(claim).await {
        Err(DurableJobStoreError::Unsupported) => {
            store
                .fail(
                    claim,
                    RUNNER_RELEASE_REASON,
                    true,
                    false,
                    arguments.max_attempts,
                )
                .await
        }
        result => result,
    };
    verdict_or_log(result, claim, "hand back durable attempt")
}

async fn bounce_pin_unavailable(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    reason: &str,
    control: &RunnerControl,
) -> Result<()> {
    match control.record_bounce(&claim.job_id) {
        PinBounceDecision::Release { backoff } => {
            let released = hand_back_claim(store, arguments, claim).await?;
            tracing::info!(
                job_id = %claim.job_id,
                generation_id = %claim.generation_pin.generation_id,
                released,
                backoff_ms = backoff.as_millis() as u64,
                reason,
                "durable job pin is archived on another reader; handed it back"
            );
            // Stay off the queue briefly so the pod holding the pin wins it.
            control.sleep(backoff).await;
        }
        PinBounceDecision::Expire { bounced_for } => {
            let failed = verdict_or_log(
                store
                    .fail(
                        claim,
                        PIN_UNAVAILABLE_REASON,
                        false,
                        false,
                        arguments.max_attempts,
                    )
                    .await,
                claim,
                "fail durable job whose pin no reader holds",
            )?;
            tracing::warn!(
                job_id = %claim.job_id,
                generation_id = %claim.generation_pin.generation_id,
                bounced_for_ms = bounced_for.as_millis() as u64,
                fence_current = failed,
                reason,
                "no reader claimed this durable job's pin within the bound; failed it for resubmission"
            );
        }
    }
    Ok(())
}

fn is_store_unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<DurableJobStoreError>(),
            Some(DurableJobStoreError::Unavailable(_))
        )
    })
}

/// NAN-3520: idle polling cost. Doubles from `poll` per consecutive empty
/// claim, capped at EMPTY_CLAIM_BACKOFF_MAX; an operator poll above the cap is
/// kept as-is (never polls faster than configured).
fn empty_claim_delay(empty_streak: u32, poll: Duration) -> Duration {
    // 2^16 covers the smallest --poll-millis (10 ms) reaching the 1 s cap.
    let exponent = empty_streak.saturating_sub(1).min(16);
    poll.saturating_mul(1_u32 << exponent)
        .min(EMPTY_CLAIM_BACKOFF_MAX.max(poll))
}

fn store_retry_delay(failure_streak: u32, poll: Duration) -> Duration {
    let exponent = failure_streak.saturating_sub(1).min(5);
    poll.saturating_mul(1_u32 << exponent).min(STORE_RETRY_MAX)
}

async fn run_claim(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    authority_validator: Option<&SharedAuthorityValidator>,
    control: &RunnerControl,
) -> Result<ClaimOutcome> {
    // NAN-2653: a claim that raced the shutdown signal never starts.
    if control.draining() {
        return Ok(ClaimOutcome::Drained);
    }
    // NAN-2653: a job this pod handed back moments ago went to the back of
    // the queue; reaching it again means nothing newer is waiting. Every slot
    // of this pod sits out the remaining backoff instead of re-bouncing it.
    if let Some(remaining) = control.bounce_hold(&claim.job_id) {
        return Ok(ClaimOutcome::BounceHold(remaining));
    }
    if arguments.trusted_local {
        let route = trusted_local_cell_route(arguments)?;
        return run_cell_claim(store, arguments, claim, authority_validator, control, &route).await;
    }
    let cell_routes = cell_route_source();
    if std::env::var_os("NANO_LAKE_CELL_ROUTES_FILE").is_some() && cell_routes.is_none() {
        bail!("cell route configuration is unusable; refusing durable claim");
    }
    if let (Some(tenant_id), Some(routes)) = (
        arguments.tenant_scope.tenant_id(),
        cell_routes,
    ) {
        if let Some(route) = routes.route(tenant_id) {
            return run_cell_claim(store, arguments, claim, authority_validator, control, &route).await;
        }
    }
    // NAN-3861: the gen1 local executor (a nanosiem-lake-worker child per
    // attempt over an archived generation pin) is retired. Every claim runs on
    // the tenant's query[T]; without a current cell route the job is handed
    // back (bounded by the pin-bounce window), never run locally.
    Ok(cell_only_without_route(arguments)
        .context("durable runner requires --cell-only: the gen1 local executor is retired")?)
}

/// Execute a hosted claim on the tenant's current query[T]. The runner keeps
/// the coordinator lease while the cell executes; losing the fence sends the
/// attempt-scoped cancellation to the cell before the runner releases it.
/// Reported once a lean cell attempt is dispatched. Must stay inside the
/// hosted coordinator's `progress.phase` allowlist (NAN-2924 shipped
/// "cell_dispatched", which the Worker refuses with 409 `invalid_phase`).
const CELL_DISPATCH_PHASE: &str = "scanning";

async fn run_cell_claim(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    authority_validator: Option<&SharedAuthorityValidator>,
    control: &RunnerControl,
    route: &LakeCellRoute,
) -> Result<ClaimOutcome> {
    route.validate_query_base().map_err(anyhow::Error::msg)?;
    if arguments.hosted_coordinator_config.is_none() && !arguments.trusted_local {
        bail!("cell search jobs require hosted coordinator fencing");
    }
    // NAN-3078: typed product views run on query[T] too, inside the same
    // retention-bound window as a search (the proof below travels with the
    // spec and query[T] enforces it). NAN-3086: Retro is one of them.
    // NAN-3088: so is a Prevalence export, whose cell relation is built over
    // the proof's clamped window (not a generation snapshot).
    if !(claim.task.is_search() || claim.task.is_lean_view()) {
        bail!("cell query runner accepts search and product-view tasks only");
    }
    if !validate_claim_authority(store, arguments, authority_validator, claim).await? {
        return Ok(ClaimOutcome::Finished);
    }
    let resource_class = select_resource_class(
        claim.resource_class, claim.task.required_scan_bytes(),
        arguments.medium_scan_bytes, arguments.large_scan_bytes,
    ).map_err(QueryTooLarge)?;
    let scan_budget_bytes = match resource_class {
        ResourceClass::Medium => arguments.medium_scan_bytes,
        ResourceClass::Large => arguments.large_scan_bytes,
    };
    let submitted_at = Utc::now();
    let mut range = claim.request.time_range.clone();
    #[cfg(feature = "enterprise")]
    let shared_scope = arguments.tenant_scope.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_scope = !matches!(arguments.tenant_scope, SearchTenantScope::Dedicated);
    let retention_proof = if shared_scope {
        let cutoff = arguments.tenant_scope.event_time_cutoff(submitted_at)
            .context("shared cell job has no retention cutoff")?;
        range.start = range.start.max(cutoff);
        if range.start >= range.end { bail!("shared cell job range expired before execution"); }
        Some(DurableResultRetentionProof::from_shared_job(
            arguments.tenant_scope, submitted_at, &range,
        )?)
    } else { None };
    let attempt_id = format!("attempt-{}-fence-{}", claim.attempt, claim.fence);
    let spec = LakeQueryJobSpec {
        schema_version: JOB_SCHEMA_VERSION,
        job_id: claim.job_id.clone(),
        attempt_id: attempt_id.clone(),
        fence_token: format!("{}:{}:{}:{}", claim.job_id, claim.attempt, claim.fence, Uuid::now_v7()),
        tenant_id: arguments.tenant_id.clone(),
        generation_id: claim.generation_pin.generation_id.clone(),
        event_config_sha256: claim.generation_pin.event_config_sha256.clone(),
        snapshot_id: claim.generation_pin.snapshot_id,
        compiler_sha256: claim.generation_pin.compiler_sha256.clone(),
        native_artifact_sha256: claim.generation_pin.native_artifact_sha256.clone(),
        hot_tail_manifest_sha256: None,
        hot_tail_snapshot_id: None,
        hot_tail_id: None,
        resource_class,
        scan_budget_bytes,
        submitted_at,
        scope_deny: claim.scope_deny.clone(),
        task: claim.task.clone(),
        request: LakeQueryJobRequest {
            dataset: claim.request.dataset.clone().unwrap_or_else(|| "logs".into()),
            query: claim.request.query.clone(),
            start: range.start.to_rfc3339(),
            end: range.end.to_rfc3339(),
            limit: claim.request.limit.unwrap_or(100),
            offset: claim.request.offset.unwrap_or(0),
            table_view: claim.request.table_view,
            anchor_us: None,
            decay: None,
            clear_boundaries: Default::default(),
            minimum_clear_revision: None,
        },
        result_page_rows: 10_000,
        retention_proof: retention_proof.clone(),
    };
    spec.validate()?;
    if !store.progress(claim, &SearchJobProgress {
        // The coordinator accepts only its closed phase set; the cell runs
        // the scan, so a dispatched attempt reports "scanning".
        phase: Some(CELL_DISPATCH_PHASE.into()), attempt: Some(claim.attempt),
        rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 0,
    }).await? { return Ok(ClaimOutcome::Finished); }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(arguments.execution_seconds.saturating_add(30)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut heartbeat = tokio::time::interval(arguments.lease / 3);
    heartbeat.tick().await;
    // NAN-3272: a lane-wait timeout (the cell's single read-write lane was
    // held by a product-state build) is retried inside this claim, under its
    // lease and fence, with exponential backoff, instead of charging the
    // attempt after one 20 s wait.
    let lane_wait_started = Instant::now();
    let mut lane_wait_retries = 0_u32;
    // NAN-3883: a cold object fetch that outlived its deadline is re-sent
    // the same way (bounded by COLD_FETCH_MAX_RESENDS and its time budget).
    // Every object that did arrive stays in the reader cache, so each
    // re-send resumes warm instead of starting the scan over.
    let mut cold_fetch_retries = 0_u32;
    // NAN-3289 P2-2: the spec travels as these exact bytes, signed with
    // this tenant's `job` key when the deployer mounted one; the cell router
    // verifies the signature before query[T] trusts the retention proof and
    // deny scope inside it.
    let spec_body = serde_json::to_vec(&spec)?;
    let spec_signature = cell_job_spec_signature(route, &spec_body)?;
    let response = 'dispatch: loop {
        if cold_fetch_retries > 0 {
            // NAN-3883: the re-send is scanning again.
            report_cell_phase(store, claim, CELL_DISPATCH_PHASE).await;
        }
        let token = route.read_router_token().map_err(anyhow::Error::msg)?;
        let mut request = client.post(format!("{}/v1/jobs/search", route.query_base_url))
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(spec_body.clone());
        if let Some(signature) = &spec_signature {
            request = request.header(nanosiem_lake_cell::tenant_token::JOB_SIGNATURE_HEADER, signature);
        }
        let request = request.send();
        tokio::pin!(request);
        let response = loop {
            tokio::select! {
                response = &mut request => match response {
                    Ok(response) => break response,
                    Err(error) => {
                        cancel_cell_attempt(&client, route, &spec).await;
                        return Err(error.into());
                    }
                },
                _ = heartbeat.tick() => {
                    let renewed = store.renew(claim, arguments.lease).await;
                    let authorized = if matches!(&renewed, Ok(true)) {
                        validate_claim_authority(store, arguments, authority_validator, claim).await
                    } else { Ok(false) };
                    if !matches!((&renewed, &authorized), (Ok(true), Ok(true))) {
                        cancel_cell_attempt(&client, route, &spec).await;
                        renewed?;
                        authorized?;
                        return Ok(ClaimOutcome::Finished);
                    }
                }
                _ = control.signalled() => {
                    cancel_cell_attempt(&client, route, &spec).await;
                    return Ok(ClaimOutcome::DrainInterrupted);
                }
            }
        };
        if response.status().is_success() {
            break 'dispatch response;
        }
        let status = response.status();
        let body = response.json::<Value>().await.ok();
        let text = |key: &str| body.as_ref()
            .and_then(|body| body.get(key).and_then(Value::as_str))
            .map(|value| value.chars().take(400).collect::<String>());
        let (reason, error) = (text("reason"), text("error"));
        if cell_attempt_not_started(status, reason.as_deref()) {
            // query[T] runs one job at a time and may still be waking. The
            // attempt never started, so hand it back without charging it.
            return Ok(ClaimOutcome::BounceHold(CELL_BUSY_HOLD));
        }
        let resend = if cell_lane_wait_timeout(status, reason.as_deref()) {
            lane_wait_retries = lane_wait_retries.saturating_add(1);
            lane_wait_backoff(lane_wait_retries, lane_wait_started.elapsed()).inspect(|backoff| tracing::warn!(
                job_id = %claim.job_id, attempt = claim.attempt, fence = claim.fence,
                retry = lane_wait_retries, backoff_ms = backoff.as_millis() as u64,
                "cell read-write lane stayed busy; re-sending the durable attempt after a backoff"
            ))
        } else if cell_cold_fetch_timeout(status, reason.as_deref()) {
            cold_fetch_retries = cold_fetch_retries.saturating_add(1);
            let backoff = cold_fetch_backoff(cold_fetch_retries, lane_wait_started.elapsed());
            if let Some(backoff) = backoff {
                tracing::warn!(
                    job_id = %claim.job_id, attempt = claim.attempt, fence = claim.fence,
                    retry = cold_fetch_retries, backoff_ms = backoff.as_millis() as u64,
                    "cold object fetch outlived its deadline; re-sending the durable attempt warm after a backoff"
                );
                // The UI shows "retrying (n)". Best effort: a coordinator
                // that predates the retry phases refuses it; the job runs on.
                report_cell_phase(store, claim, cold_fetch_retry_phase(cold_fetch_retries)).await;
            }
            backoff
        } else {
            None
        };
        if let Some(backoff) = resend {
            // Hold the claim through the backoff: keep the lease and
            // authority current; nothing runs in the cell meanwhile.
            let resume = tokio::time::sleep(backoff);
            tokio::pin!(resume);
            loop {
                tokio::select! {
                    _ = &mut resume => break,
                    _ = heartbeat.tick() => {
                        let renewed = store.renew(claim, arguments.lease).await;
                        let authorized = if matches!(&renewed, Ok(true)) {
                            validate_claim_authority(store, arguments, authority_validator, claim).await
                        } else { Ok(false) };
                        if !matches!((&renewed, &authorized), (Ok(true), Ok(true))) {
                            renewed?;
                            authorized?;
                            return Ok(ClaimOutcome::Finished);
                        }
                    }
                    // Nothing is running in the cell: a free hand-back.
                    _ = control.signalled() => return Ok(ClaimOutcome::Drained),
                }
            }
            continue 'dispatch;
        }
        cancel_cell_attempt(&client, route, &spec).await;
        if cell_query_too_large(status, reason.as_deref(), error.as_deref()) {
            return Err(anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE))
                .context(format!(
                    "cell job returned HTTP {status} (query_budget_exhausted): {}",
                    error.as_deref().unwrap_or("query memory budget exceeded")
                )));
        }
        if cell_statement_timed_out(status, error.as_deref()) {
            return Err(anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_TIME_MESSAGE))
                .context(format!(
                    "cell job returned HTTP {status} (statement time limit): {}",
                    error.as_deref().unwrap_or("TIMEOUT_EXCEEDED")
                )));
        }
        // The cell's typed refusal (e.g. a view past its envelope, or a
        // window the retention cutoff has passed) is the job's failure.
        match (reason, error) {
            (Some(reason), Some(error)) => bail!("cell job returned HTTP {status} ({reason}): {error}"),
            _ => bail!("cell search job returned HTTP {status}"),
        }
    };
    let body: Value = response.json().await?;
    if body.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("cell search response did not confirm completion");
    }
    let artifact: ResultArtifactRef = serde_json::from_value(body.get("result")
        .cloned().context("cell search response has no result reference")?)?;
    // The same function query[T]'s tests prove their exchanged-credential
    // commits against (NAN-3042).
    let expected = nanosiem_lake_worker::job::expected_manifest_uri(
        &arguments.result_root, &arguments.tenant_id, &claim.job_id, &attempt_id,
    );
    if artifact.manifest_uri != expected {
        bail!("cell search returned a result outside the tenant's fenced attempt");
    }
    if !validate_claim_authority(store, arguments, authority_validator, claim).await? {
        cancel_cell_attempt(&client, route, &spec).await;
        return Ok(ClaimOutcome::Finished);
    }
    let result = SearchJobResultRef {
        tenant_id: claim.tenant_id,
        manifest_uri: artifact.manifest_uri,
        manifest_sha256: artifact.manifest_sha256,
        rows: artifact.rows,
        parts: artifact.parts,
        has_more: artifact.has_more,
        page_rows: artifact.page_rows,
        retention_proof,
    };
    if !store.progress(claim, &SearchJobProgress {
        phase: Some("publishing_result".into()), attempt: Some(claim.attempt),
        rows_scanned: result.rows, rows_total: result.rows, percent: 100, elapsed_ms: 0,
    }).await? {
        cancel_cell_attempt(&client, route, &spec).await;
        return Ok(ClaimOutcome::Finished);
    }
    if !store.complete(claim, &result).await? {
        tracing::warn!(job_id = %claim.job_id, "cell result became orphaned after fence changed");
    }
    Ok(ClaimOutcome::Finished)
}

/// Hold before a busy or waking query[T] sees the same job again.
const CELL_BUSY_HOLD: Duration = Duration::from_secs(5);

/// NAN-3272: first backoff after a cell lane-wait timeout; doubles per retry.
const LANE_WAIT_RETRY_BASE: Duration = Duration::from_secs(5);
/// NAN-3272: the longest single lane-wait backoff.
const LANE_WAIT_RETRY_MAX: Duration = Duration::from_secs(60);
/// NAN-3272: how long one claimed attempt keeps re-sending through lane-wait
/// timeouts before the attempt is charged. Background jobs can wait.
const LANE_WAIT_RETRY_BUDGET: Duration = Duration::from_secs(600);

/// query[T] could not get its read-write lane before the lane-wait bound
/// (503 `lane_wait_timeout`). The cell dropped the attempt's record, so the
/// same fenced attempt may be re-sent.
fn cell_lane_wait_timeout(status: reqwest::StatusCode, reason: Option<&str>) -> bool {
    status.as_u16() == 503 && reason == Some("lane_wait_timeout")
}

/// NAN-3272: the backoff before lane-wait retry `retry` (1-based), or `None`
/// once `waited` plus that backoff would pass [`LANE_WAIT_RETRY_BUDGET`].
fn lane_wait_backoff(retry: u32, waited: Duration) -> Option<Duration> {
    let exponent = retry.saturating_sub(1).min(8);
    let backoff = LANE_WAIT_RETRY_BASE.saturating_mul(1_u32 << exponent).min(LANE_WAIT_RETRY_MAX);
    (waited.saturating_add(backoff) <= LANE_WAIT_RETRY_BUDGET).then_some(backoff)
}

/// NAN-3883: query[T] ran the attempt but a cold object fetch outlived its
/// deadline (503 `cold_fetch_timeout`). The cell dropped the attempt's
/// record and kept every object that did arrive, so the same fenced attempt
/// is re-sent instead of failing the job (which cost the user a re-run once
/// the job's two attempts were spent).
fn cell_cold_fetch_timeout(status: reqwest::StatusCode, reason: Option<&str>) -> bool {
    status.as_u16() == 503 && reason == Some("cold_fetch_timeout")
}

/// NAN-3883: re-sends after cold-fetch timeouts within one claim (five sends
/// in all).
const COLD_FETCH_MAX_RESENDS: u32 = 4;
/// NAN-3883: first backoff after a cold-fetch timeout; doubles per retry.
const COLD_FETCH_RETRY_BASE: Duration = Duration::from_secs(10);
/// NAN-3883: the longest single cold-fetch backoff.
const COLD_FETCH_RETRY_MAX: Duration = Duration::from_secs(60);
/// NAN-3883: how long one claim keeps re-sending through cold-fetch
/// timeouts, measured from its first dispatch.
const COLD_FETCH_RETRY_BUDGET: Duration = Duration::from_secs(600);

/// NAN-3883: the backoff before cold-fetch re-send `retry` (1-based), or
/// `None` once the re-sends or the time budget are spent.
fn cold_fetch_backoff(retry: u32, waited: Duration) -> Option<Duration> {
    if retry == 0 || retry > COLD_FETCH_MAX_RESENDS {
        return None;
    }
    let backoff = COLD_FETCH_RETRY_BASE.saturating_mul(1_u32 << (retry - 1).min(8)).min(COLD_FETCH_RETRY_MAX);
    (waited.saturating_add(backoff) <= COLD_FETCH_RETRY_BUDGET).then_some(backoff)
}

/// NAN-3883: the progress phase of cold-fetch re-send `retry` (1-based),
/// inside the hosted coordinator's closed allowlist.
fn cold_fetch_retry_phase(retry: u32) -> &'static str {
    match retry {
        0 | 1 => "retrying_1",
        2 => "retrying_2",
        3 => "retrying_3",
        _ => "retrying_4",
    }
}

/// Report `phase` for this claim; best effort (a refusal is logged, never
/// charged to the job).
async fn report_cell_phase(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    phase: &str,
) {
    let progress = SearchJobProgress {
        phase: Some(phase.into()), attempt: Some(claim.attempt),
        rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 0,
    };
    if let Err(error) = store.progress(claim, &progress).await {
        tracing::debug!(job_id = %claim.job_id, phase, %error, "durable job phase was not recorded");
    }
}

/// A cell-only runner has no gen1 executor. A claim for a tenant whose cell
/// route is absent (mid-move, or the routes file not yet reloaded) is handed
/// back like a pin held elsewhere: bounded by the pin-bounce window, then
/// failed for resubmission. It never falls through to the gen1 path.
fn cell_only_without_route(arguments: &Arguments) -> Option<ClaimOutcome> {
    arguments.cell_only.then(|| {
        ClaimOutcome::PinUnavailable("tenant has no current lean cell route on this runner".into())
    })
}

/// query[T] refused before recording the attempt: another job holds its
/// single job lane (429 `job_busy`) or its prewarm is incomplete (503
/// `not_ready`). Any other refusal is charged to the job.
fn cell_attempt_not_started(status: reqwest::StatusCode, reason: Option<&str>) -> bool {
    matches!((status.as_u16(), reason), (429, Some("job_busy")) | (503, Some("not_ready")))
}

/// NAN-3289: names the file holding this runner's tenant `job` key (a
/// `nct1.` value the deployer derives for exactly this tenant and cell).
pub const LAKE_CELL_JOB_SPEC_KEY_FILE_ENV: &str = "NANO_LAKE_CELL_JOB_SPEC_KEY_FILE";

/// The `x-nano-cell-job-signature` for `body` on `route`, or `None` when no
/// job key is mounted (the router then admits the spec only in its legacy
/// mode). A configured but unusable key is an error: never send unsigned
/// by accident.
fn cell_job_spec_signature(route: &LakeCellRoute, body: &[u8]) -> Result<Option<String>> {
    let Some(path) = std::env::var_os(LAKE_CELL_JOB_SPEC_KEY_FILE_ENV).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let key = LakeCellRoute::read_token_file(std::path::Path::new(&path)).map_err(anyhow::Error::msg)
        .context("cell job spec key")?;
    sign_cell_job_spec(route, &key, body).map(Some)
}

fn sign_cell_job_spec(route: &LakeCellRoute, key: &str, body: &[u8]) -> Result<String> {
    let cell = route.cell_id().context("the cell route names no cell id to sign the job spec for")?;
    Ok(nanosiem_lake_cell::tenant_token::sign_job_spec(key, &route.tenant_id.as_hyphenated().to_string(), &cell, body))
}

async fn cancel_cell_attempt(client: &reqwest::Client, route: &LakeCellRoute, spec: &LakeQueryJobSpec) {
    let Ok(token) = route.read_router_token() else {
        tracing::warn!(job_id = %spec.job_id, "cell attempt cancellation token was unavailable");
        return;
    };
    let response = client.post(format!("{}/v1/jobs/search/cancel", route.query_base_url))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "tenant_id": spec.tenant_id, "job_id": spec.job_id, "attempt_id": spec.attempt_id,
        }))
        .timeout(Duration::from_secs(5))
        .send().await;
    if !matches!(response, Ok(ref response) if response.status().is_success()) {
        tracing::warn!(job_id = %spec.job_id, "cell attempt cancellation was not acknowledged");
    }
}

/// A dependency outage closes this attempt without revoking the principal.
/// The store releases the lease and bounds retries with its execution-failure
/// budget. Backoff prevents this runner from hot-looping on the released job.
async fn validate_claim_authority(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    arguments: &Arguments,
    validator: Option<&SharedAuthorityValidator>,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
) -> Result<bool> {
    apply_claim_authority(
        store,
        claim,
        current_claim_authority(validator, arguments.tenant_scope, claim).await,
        arguments.max_attempts,
        arguments.poll,
    )
    .await
}

async fn apply_claim_authority(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
    authority: Result<bool, AuthorityUnavailable>,
    max_attempts: u32,
    poll: Duration,
) -> Result<bool> {
    match authority {
        Ok(true) => Ok(true),
        Ok(false) => {
            cancel_current_claim(store, claim).await?;
            Ok(false)
        }
        Err(AuthorityUnavailable) => {
            store
                .fail(
                    claim,
                    "Search authority temporarily unavailable",
                    true,
                    false,
                    max_attempts,
                )
                .await?;
            tokio::time::sleep(store_retry_delay(claim.attempt, poll)).await;
            Ok(false)
        }
    }
}

async fn cancel_current_claim(
    store: &dyn nanosiem_core::search::job_runner_store::DurableJobRunnerStore,
    claim: &nanosiem_core::search::job_runner_store::RunnerClaim,
) -> Result<()> {
    let changed = store.cancel_claim(claim).await?;
    tracing::debug!(job_id = %claim.job_id, fence_current = changed,
        "attempt-fenced cancellation after authority revocation");
    Ok(())
}

const SCAN_CAPACITY_REASON: &str = nanosiem_core::search::QUERY_TOO_LARGE_SCAN_MESSAGE;

/// NAN-3911: a durable attempt that can never fit (the scan exceeds the
/// largest resource class, or query[T]'s per-query memory budget refused it).
/// Deterministic: the job fails at once with this static, user-facing
/// category (`query_too_large`) instead of spending retry attempts and then
/// surfacing "isolated query execution failed".
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct QueryTooLarge(&'static str);

/// NAN-4290: the claim is a small-lane job (not yet promoted to large).
fn small_lane_job(claim: &DurableSearchJobClaim) -> bool {
    nanosiem_core::search::small_job_lane(
        &claim.task,
        claim.request.time_range.start,
        claim.request.time_range.end,
        claim.resource_class == DurableQueryResourceClass::Large,
    )
}

fn query_too_large(error: &anyhow::Error) -> Option<&'static str> {
    error.chain().find_map(|cause| cause.downcast_ref::<QueryTooLarge>().map(|too_large| too_large.0))
}

/// NAN-3911: query[T]'s memory budget refused the durable attempt itself
/// (503 `query_budget_exhausted`: a per-query chDB memory limit or an
/// oversized result). The per-statement cap is fixed by the role's memory,
/// so the same attempt would fail the same way. A refusal of the engine-wide
/// total (`(total) memory limit`) can come from concurrent work and stays a
/// retryable attempt failure.
/// NAN-4277 (F18): the cell's job statement ran past its statement time
/// limit (chDB `TIMEOUT_EXCEEDED`; a whole-window job statement has
/// `JOB_STATEMENT_SECONDS`, and a newest-first job already halved its slow
/// chunks). Re-running the same attempt would hold the tenant's one durable
/// lane for the same time again (a large hosted tenant, 2026-10-20: a 7 d keyword
/// count failed twice at 120 s, ~5 min of lane), so it fails once with the
/// actionable time-limit category.
fn cell_statement_timed_out(status: reqwest::StatusCode, error: Option<&str>) -> bool {
    status.is_server_error() && error.is_some_and(|error| error.contains("TIMEOUT_EXCEEDED"))
}

fn cell_query_too_large(status: reqwest::StatusCode, reason: Option<&str>, error: Option<&str>) -> bool {
    status.as_u16() == 503
        && reason == Some("query_budget_exhausted")
        && !error.is_some_and(|error| error.contains("(total)"))
}

fn select_resource_class(
    requested: DurableQueryResourceClass, required: u64, medium: u64, large: u64,
) -> Result<ResourceClass, &'static str> {
    if required > large {
        Err(SCAN_CAPACITY_REASON)
    } else if requested == DurableQueryResourceClass::Large || required > medium {
        Ok(ResourceClass::Large)
    } else {
        Ok(ResourceClass::Medium)
    }
}

#[cfg(test)]
mod shed_admission_tests {
    use super::*;

    #[test]
    fn shed_at_four_gib_promotes_before_starting_a_worker() {
        let task = nanosiem_core::search::DurableLakeTask::shed_from_resource_error(
            "memory; estimated_bytes=3966598766; budget_bytes=4294967296");
        assert_eq!(task.required_scan_bytes(), 4 << 30);
        assert_eq!(select_resource_class(DurableQueryResourceClass::Medium,
            task.required_scan_bytes(), 1 << 30, 8 << 30).unwrap(), ResourceClass::Large);
        let wire = serde_json::to_vec(&task).unwrap();
        let restored: nanosiem_core::search::DurableLakeTask = serde_json::from_slice(&wire).unwrap();
        assert_eq!(restored, task);
    }

    #[test]
    fn over_max_is_terminal_and_readable() {
        let reason = select_resource_class(DurableQueryResourceClass::Medium,
            (8 << 30) + 1, 1 << 30, 8 << 30).unwrap_err();
        assert!(reason.contains("Narrow the time range"));
    }
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> Result<Self> {
        let mut map = std::collections::BTreeMap::new();
        let mut once = false;
        let mut cell_only = false;
        let mut trusted_local = false;
        while let Some(argument) = values.next() {
            if argument == "--once" {
                once = true;
                continue;
            }
            if argument == "--trusted-local" {
                trusted_local = true;
                continue;
            }
            if argument == "--cell-only" {
                cell_only = true;
                continue;
            }
            let value = values
                .next()
                .with_context(|| format!("{argument} requires a value"))?;
            if map.insert(argument.clone(), value).is_some() {
                bail!("duplicate argument: {argument}");
            }
        }
        let hosted_coordinator_config =
            map.remove("--hosted-coordinator-config").map(PathBuf::from);
        if hosted_coordinator_config
            .as_deref()
            .is_some_and(|p| !p.is_absolute())
        {
            bail!("--hosted-coordinator-config must be an absolute private file path");
        }
        let redis_url = map
            .remove("--redis-url")
            .or_else(|| std::env::var("REDIS_URL").ok())
            .or_else(||hosted_coordinator_config.as_ref().map(|_|String::new()))
            .context("--redis-url or REDIS_URL is required unless explicit hosted test config is supplied")?;
        let database_url = map
            .remove("--database-url")
            .or_else(|| std::env::var("DATABASE_URL").ok())
            .filter(|value| !value.trim().is_empty());
        let tenant_id = map
            .remove("--tenant-id")
            .or_else(|| std::env::var("NANO_LAKE_TENANT_ID").ok())
            .context("--tenant-id or NANO_LAKE_TENANT_ID is required")?;
        let tenant_scope =
            search_tenant_scope(std::env::var("DEPLOYMENT_MODE").ok().as_deref(), &tenant_id)?;
        if hosted_coordinator_config.is_some()
            && matches!(tenant_scope, SearchTenantScope::Dedicated)
        {
            bail!("hosted coordinator test config requires enterprise_shared mode");
        }
        if trusted_local {
            if !cell_only || !matches!(tenant_scope, SearchTenantScope::Dedicated)
                || hosted_coordinator_config.is_some()
            {
                bail!("--trusted-local requires --cell-only dedicated mode without hosted coordinator config");
            }
            let tenant = Uuid::parse_str(&tenant_id).context("trusted-local tenant ID must be a UUID")?;
            if tenant.get_version_num() != 4 || tenant.to_string() != tenant_id {
                bail!("trusted-local tenant ID must be a canonical UUIDv4");
            }
        }
        let assignment_revision = match map.remove("--assignment-revision") {
            Some(value) => Some(
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|revision| (1..=1_000_000).contains(revision))
                    .context(
                        "--assignment-revision must be a positive worker assignment revision",
                    )?,
            ),
            None => None,
        };
        if assignment_revision.is_none() && !matches!(tenant_scope, SearchTenantScope::Dedicated) {
            bail!("enterprise-shared durable runner requires --assignment-revision");
        }
        let result_root = map
            .remove("--result-root")
            .or_else(|| std::env::var("NANO_LAKE_JOB_RESULT_ROOT").ok())
            .context("--result-root or NANO_LAKE_JOB_RESULT_ROOT is required")?;
        if trusted_local && result_root != nanosiem_lake_worker::part_query::job_results::job_results_root(&tenant_id) {
            bail!("trusted-local result root must be this tenant's canonical durable-result root");
        }
        // NAN-3861: the gen1 local executor is retired; query[T] executes
        // every attempt over the tenant's cell route.
        if !cell_only {
            bail!("the durable runner requires --cell-only: the gen1 local executor (--worker-binary, --generation-config-root) is retired");
        }
        if map.contains_key("--worker-binary") || map.contains_key("--generation-config-root") {
            bail!("--cell-only runs no gen1 attempt; drop --worker-binary and --generation-config-root");
        }
        if hosted_coordinator_config.is_none() && !trusted_local {
            bail!("--cell-only requires --hosted-coordinator-config (cell jobs need hosted fencing)");
        }
        let job_signing_key_file = map
            .remove("--job-signing-key-file")
            .or_else(|| std::env::var("NANO_LAKE_JOB_SIGNING_KEY_FILE").ok())
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        if job_signing_key_file
            .as_deref()
            .is_some_and(|path| !path.is_absolute())
        {
            bail!("--job-signing-key-file must be an absolute path");
        }
        let worker_id = map
            .remove("--worker-id")
            .unwrap_or_else(|| format!("runner-{}-{}", std::process::id(), Uuid::now_v7()));
        let lease_seconds =
            parse_bounded(&mut map, "--lease-seconds", DEFAULT_LEASE_SECONDS, 5, 3_600)?;
        let poll_millis =
            parse_bounded(&mut map, "--poll-millis", DEFAULT_POLL_MILLIS, 10, 60_000)?;
        let max_attempts = parse_bounded(&mut map, "--max-attempts", DEFAULT_MAX_ATTEMPTS, 1, 10)?;
        let concurrency = parse_bounded(&mut map, "--concurrency", 2_usize, 1, 16)?;
        let small_lane_slots = parse_bounded(&mut map, "--small-lane-slots", 0_usize, 0, 4)?;
        if small_lane_slots > 0 && hosted_coordinator_config.is_none() {
            bail!("--small-lane-slots requires --hosted-coordinator-config (only the hosted coordinator has claim lanes)");
        }
        let medium_scan_bytes = parse_bounded(
            &mut map,
            "--medium-scan-bytes",
            DEFAULT_MEDIUM_SCAN_BYTES,
            1_u64 << 30,
            1_u64 << 50,
        )?;
        let large_scan_bytes = parse_bounded(
            &mut map,
            "--large-scan-bytes",
            DEFAULT_LARGE_SCAN_BYTES,
            medium_scan_bytes,
            1_u64 << 50,
        )?;
        let execution_seconds = parse_bounded(
            &mut map,
            "--execution-seconds",
            DEFAULT_EXECUTION_SECONDS,
            30,
            86_400,
        )?;
        let drain_seconds = parse_seconds_setting(
            map.remove("--drain-seconds")
                .or_else(|| std::env::var(DRAIN_SECONDS_ENV).ok()),
            DRAIN_SECONDS_ENV,
            DEFAULT_DRAIN_SECONDS,
            1,
            MAX_DRAIN_SECONDS,
        )?;
        let pin_bounce_seconds = parse_seconds_setting(
            map.remove("--pin-bounce-seconds")
                .or_else(|| std::env::var(PIN_BOUNCE_SECONDS_ENV).ok()),
            PIN_BOUNCE_SECONDS_ENV,
            DEFAULT_PIN_BOUNCE_SECONDS,
            5,
            3_600,
        )?;
        if max_attempts > 1 && large_scan_bytes <= medium_scan_bytes {
            bail!(
                "durable large resource class must exceed the medium scan budget when retries are enabled"
            );
        }
        if !(result_root.starts_with("s3://") || result_root.starts_with("file://"))
            || tenant_id.is_empty()
            || worker_id.is_empty()
            || worker_id.len() > 256
        {
            bail!("durable job runner path, tenant, worker, or result configuration is invalid");
        }
        if !map.is_empty() {
            bail!(
                "unknown arguments: {}",
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        Ok(Self {
            redis_url,
            hosted_coordinator_config,
            database_url,
            tenant_id,
            tenant_scope,
            assignment_revision,
            worker_id,
            cell_only,
            trusted_local,
            job_signing_key_file,
            result_root,
            lease: Duration::from_secs(lease_seconds),
            poll: Duration::from_millis(poll_millis),
            max_attempts,
            medium_scan_bytes,
            large_scan_bytes,
            execution_seconds,
            concurrency,
            small_lane_slots,
            drain: Duration::from_secs(drain_seconds),
            pin_bounce_bound: Duration::from_secs(pin_bounce_seconds),
            once,
        })
    }
}

fn search_tenant_scope(
    deployment_mode: Option<&str>,
    tenant_id: &str,
) -> Result<SearchTenantScope> {
    match deployment_mode {
        #[cfg(feature = "enterprise")]
        Some("enterprise_shared") => enterprise_shared_tenant_scope(tenant_id),
        #[cfg(not(feature = "enterprise"))]
        Some("enterprise_shared") => {
            let _ = tenant_id;
            bail!("enterprise-shared durable runner requires an enterprise build")
        }
        None | Some("") | Some("managed") | Some("selfhosted") | Some("self-hosted")
        | Some("demo") => Ok(SearchTenantScope::dedicated()),
        Some(value) => bail!("invalid DEPLOYMENT_MODE {value:?} for durable job runner"),
    }
}

#[cfg(feature = "enterprise")]
fn enterprise_shared_tenant_scope(tenant_id: &str) -> Result<SearchTenantScope> {
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = tenant_id;
        bail!("enterprise-shared durable runner requires an enterprise build");
    }

    #[cfg(feature = "enterprise")]
    {
        let tenant_id = Uuid::parse_str(tenant_id)
            .context("enterprise-shared durable runner tenant ID must be a UUID")?;
        SearchTenantScope::enterprise_shared(Some(tenant_id)).map_err(Into::into)
    }
}

/// A seconds setting from a flag or its environment variable; blank means
/// the default. Out-of-range values refuse to boot rather than clamp.
fn parse_seconds_setting(
    value: Option<String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64> {
    let value = match value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => value
            .parse::<u64>()
            .with_context(|| format!("{key} must be a whole number of seconds"))?,
        None => default,
    };
    if !(min..=max).contains(&value) {
        bail!("{key} must be between {min} and {max} seconds");
    }
    Ok(value)
}

fn parse_bounded<T>(
    map: &mut std::collections::BTreeMap<String, String>,
    key: &str,
    default: T,
    min: T,
    max: T,
) -> Result<T>
where
    T: Copy + Ord + std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value = map
        .remove(key)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        bail!("{key} is outside its safety bound");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    #[ignore = "requires an isolated NANO_TEST_REDIS_URL"]
    async fn claim_authority_outage_retries_then_runs_and_revocation_has_reason() {
        use nanosiem_core::auth::ScopeSet;
        use nanosiem_core::search::job_runner_store::DurableJobRunnerStore;
        use nanosiem_core::search::{
            DurableLakeTask, QueryPriority, SearchJobStatus, SearchJobStore,
        };
        let store = RedisJobStore::connect(&std::env::var("NANO_TEST_REDIS_URL").unwrap())
            .await
            .unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "query":"* | stats count", "time_range":{"start":Utc::now(),"end":Utc::now()},
            "skip_histogram":false,"skip_field_stats":false,"use_cache":false,"table_view":false,"async_mode":true
        })).unwrap();
        let pin = DurableLakeGenerationPin {
            generation_id: "event-42-aaaaaaaaaaaa".to_string(),
            event_config_sha256: "a".repeat(64),
            snapshot_id: 42,
            iceberg_metadata_location: Some(
                "s3://lake/warehouse/tenant-a/events/metadata/00042.metadata.json".to_string(),
            ),
            compiler_sha256: "b".repeat(64),
            native_artifact_sha256: "c".repeat(64),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
        };
        let id = store
            .create_durable_queued(
                request,
                &DurableLakeTask::SearchNplV1,
                Uuid::now_v7(),
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
                &pin,
                None,
            )
            .await
            .unwrap();
        let lease = Duration::from_secs(30);
        let first = DurableJobRunnerStore::claim(&store, "authority-test", lease)
            .await
            .unwrap()
            .unwrap();
        assert!(!apply_claim_authority(
            &store,
            &first,
            Err(AuthorityUnavailable),
            3,
            Duration::from_millis(1)
        )
        .await
        .unwrap());
        let queued = store.get(&id).await.unwrap();
        assert_eq!(queued.status, SearchJobStatus::Queued);
        assert!(!queued.error.unwrap().is_empty());
        assert!(
            !DurableJobRunnerStore::renew(&store, &first, lease)
                .await
                .unwrap(),
            "released lease must be fenced"
        );
        let retry = DurableJobRunnerStore::claim(&store, "authority-test", lease)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retry.attempt, first.attempt + 1);
        assert!(
            apply_claim_authority(&store, &retry, Ok(true), 3, Duration::from_millis(1))
                .await
                .unwrap(),
            "recovered authority permits process start"
        );
        assert_eq!(
            store.get(&id).await.unwrap().status,
            SearchJobStatus::Running
        );
        assert!(
            !apply_claim_authority(&store, &retry, Ok(false), 3, Duration::from_millis(1))
                .await
                .unwrap()
        );
        let cancelled = store.get(&id).await.unwrap();
        assert_eq!(cancelled.status, SearchJobStatus::Cancelled);
        assert!(cancelled.error.unwrap().contains("authority revoked"));
        store.remove(&id).await;
    }

    #[test]
    fn claim_rejections_are_distinct_from_configuration_and_store_failures() {
        let rejected = anyhow::Error::from(DurableJobStoreError::ClaimRejected).context("claim");
        assert!(is_claim_rejection(&rejected));
        assert!(!is_signature_rejection(&rejected));
        assert!(!is_store_unavailable(&rejected));
        for error in [
            DurableJobStoreError::Unsupported,
            DurableJobStoreError::Invalid("configuration".to_string()),
            DurableJobStoreError::Unavailable("timeout".to_string()),
            DurableJobStoreError::SignatureRejected("signature".to_string()),
        ] {
            assert!(!is_claim_rejection(&anyhow::Error::from(error)));
        }
    }

    #[test]
    fn signature_rejections_are_counted_and_distinguished_from_outages() {
        let rejected = anyhow::Error::from(DurableJobStoreError::SignatureRejected(
            "signature does not verify".to_string(),
        ))
        .context("claim");
        let unavailable =
            anyhow::Error::from(DurableJobStoreError::Unavailable("timeout".to_string()));
        assert!(is_signature_rejection(&rejected));
        assert!(!is_store_unavailable(&rejected));
        assert!(!is_signature_rejection(&unavailable));
        let before = SIGNATURE_REJECTIONS.load(Ordering::Relaxed);
        let total = record_signature_rejection(&rejected);
        assert!(total > before);
        assert_eq!(SIGNATURE_REJECTIONS.load(Ordering::Relaxed), total);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_runner_requires_uuid_tenant_and_dedicated_modes_are_unchanged() {
        let tenant = Uuid::from_u128(0xa);

        #[cfg(feature = "enterprise")]
        {
            assert_eq!(
                search_tenant_scope(Some("enterprise_shared"), &tenant.to_string()).unwrap(),
                SearchTenantScope::EnterpriseShared(tenant)
            );
        }

        #[cfg(not(feature = "enterprise"))]
        {
            let error = search_tenant_scope(Some("enterprise_shared"), &tenant.to_string())
                .unwrap_err()
                .to_string();
            assert!(error.contains("requires an enterprise build"));
        }

        assert!(search_tenant_scope(Some("enterprise_shared"), "tenant-a").is_err());
        assert_eq!(
            search_tenant_scope(Some("managed"), "tenant-a").unwrap(),
            SearchTenantScope::dedicated()
        );
        assert!(search_tenant_scope(Some("shared"), "tenant-a").is_err());
    }

    #[test]
    fn only_transient_store_failures_are_retried() {
        let unavailable =
            anyhow::Error::new(DurableJobStoreError::Unavailable("timed out".to_string()))
                .context("renew durable lease");
        assert!(is_store_unavailable(&unavailable));

        let invalid = anyhow::Error::new(DurableJobStoreError::Invalid(
            "malformed queue state".to_string(),
        ));
        assert!(!is_store_unavailable(&invalid));
    }

    #[test]
    fn store_retry_backoff_is_bounded() {
        let poll = Duration::from_millis(250);
        assert_eq!(store_retry_delay(1, poll), Duration::from_millis(250));
        assert_eq!(store_retry_delay(3, poll), Duration::from_secs(1));
        assert_eq!(store_retry_delay(99, poll), STORE_RETRY_MAX);
    }

    #[test]
    fn empty_claim_backoff_caps_claim_latency_at_one_second() {
        let poll = Duration::from_millis(250);
        assert_eq!(empty_claim_delay(1, poll), poll);
        assert_eq!(empty_claim_delay(2, poll), Duration::from_millis(500));
        assert_eq!(empty_claim_delay(3, poll), EMPTY_CLAIM_BACKOFF_MAX);
        assert_eq!(empty_claim_delay(u32::MAX, poll), EMPTY_CLAIM_BACKOFF_MAX);
        // A slower operator-configured poll is never shortened or lengthened.
        let slow = Duration::from_secs(5);
        assert_eq!(empty_claim_delay(1, slow), slow);
        assert_eq!(empty_claim_delay(9, slow), slow);
        // A faster one still backs off to the cap.
        assert_eq!(empty_claim_delay(9, Duration::from_millis(10)), EMPTY_CLAIM_BACKOFF_MAX);
    }

    /// NAN-3559: request-count model of one idle runner slot (the lean
    /// deployment runs `--concurrency 1`, one replica). Every store call costs
    /// one simulated coordinator round trip.
    #[derive(Debug)]
    struct IdleCoordinator {
        claim_recovers: bool,
        round_trip: Duration,
        reconciles: AtomicU64,
        claims: std::sync::Mutex<Vec<tokio::time::Instant>>,
    }

    #[async_trait::async_trait]
    impl nanosiem_core::search::job_runner_store::DurableJobRunnerStore for IdleCoordinator {
        async fn reconcile(&self, _max_attempts: u32) -> std::result::Result<usize, DurableJobStoreError> {
            tokio::time::sleep(self.round_trip).await;
            self.reconciles.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        }
        fn claim_recovers_expired_leases(&self) -> bool {
            self.claim_recovers
        }
        async fn claim(
            &self,
            _owner: &str,
            _lease: Duration,
        ) -> std::result::Result<Option<nanosiem_core::search::job_runner_store::RunnerClaim>, DurableJobStoreError> {
            self.claims.lock().unwrap().push(tokio::time::Instant::now());
            tokio::time::sleep(self.round_trip).await;
            Ok(None)
        }
        async fn renew(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: Duration)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn progress(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &nanosiem_core::search::SearchJobProgress)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn complete(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &nanosiem_core::search::SearchJobResultRef)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn fail(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &str, _: bool, _: bool, _: u32)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn cancel_claim(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
    }

    const IDLE_HOUR: Duration = Duration::from_secs(3_600);
    /// Roughly the runner -> Worker -> DO round trip the 10-10 measurement implies.
    const IDLE_ROUND_TRIP: Duration = Duration::from_millis(70);

    /// Runs one runner slot against an empty queue for a simulated hour and
    /// returns (reconcile requests, claim instants).
    async fn idle_hour(claim_recovers: bool) -> (u64, Vec<tokio::time::Instant>) {
        let directory = tempfile::tempdir().unwrap();
        let arguments = runner_arguments(&directory, &[]).unwrap();
        assert_eq!(arguments.poll, Duration::from_millis(DEFAULT_POLL_MILLIS));
        let store = IdleCoordinator {
            claim_recovers,
            round_trip: IDLE_ROUND_TRIP,
            reconciles: AtomicU64::new(0),
            claims: std::sync::Mutex::new(Vec::new()),
        };
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let ran = tokio::time::timeout(IDLE_HOUR, runner_loop(&store, &arguments, None, &control, SlotLane::General)).await;
        assert!(ran.is_err(), "an idle runner keeps polling for the whole hour");
        let claims = store.claims.lock().unwrap().clone();
        (store.reconciles.load(Ordering::Relaxed), claims)
    }

    /// NAN-3559: an idle lean tenant's coordinator saw ~6.3k requests/h
    /// (~1.75/s) after the NAN-3520 1 s backoff, because every poll was
    /// reconcile + claim. The hosted store now polls with claim alone.
    #[tokio::test(start_paused = true)]
    async fn idle_hosted_runner_makes_at_most_one_coordinator_request_per_second() {
        let (reconciles, claims) = idle_hour(true).await;
        assert_eq!(reconciles, 0, "the hosted claim already recovers expired leases");
        let requests = claims.len() as u64;
        assert!(requests <= IDLE_HOUR.as_secs(), "{requests} requests in an idle hour exceed 1/s");
        assert!(requests >= 3_300, "{requests}: idle polling must not slow past the 1 s cap");
        // A job queued at any instant is claimed by the next poll: at most the
        // backoff cap plus one round trip later.
        let worst = claims.windows(2).map(|pair| pair[1] - pair[0]).max().unwrap();
        assert!(worst <= EMPTY_CLAIM_BACKOFF_MAX + IDLE_ROUND_TRIP, "pickup latency {worst:?}");
    }

    /// The pre-NAN-3559 loop shape, still used by Redis stores: reconcile
    /// then claim. Over the same simulated hour it reproduces the measured
    /// ~6.3k coordinator requests, which is what pinned the root cause.
    #[tokio::test(start_paused = true)]
    async fn idle_redis_runner_keeps_reconcile_then_claim() {
        let (reconciles, claims) = idle_hour(false).await;
        let claims = claims.len() as u64;
        assert!(reconciles.abs_diff(claims) <= 1, "{reconciles} reconciles vs {claims} claims");
        let requests = reconciles + claims;
        assert!((6_200..=6_400).contains(&requests), "{requests} requests: the NAN-3559 measurement was ~6.3k/h");
    }
    /// NAN-4290: a coordinator with one general and one small-lane queue
    /// view, both empty; counts each lane's claims. `small_refused`: a
    /// coordinator that predates the lane (409 `invalid_command`).
    #[derive(Debug, Default)]
    struct LaneCoordinator {
        small_refused: bool,
        general_claims: AtomicU64,
        small_claims: AtomicU64,
    }

    #[async_trait::async_trait]
    impl nanosiem_core::search::job_runner_store::DurableJobRunnerStore for LaneCoordinator {
        async fn reconcile(&self, _: u32) -> std::result::Result<usize, DurableJobStoreError> { unreachable!("hosted claims recover leases") }
        fn claim_recovers_expired_leases(&self) -> bool { true }
        async fn claim(&self, _: &str, _: Duration)
            -> std::result::Result<Option<nanosiem_core::search::job_runner_store::RunnerClaim>, DurableJobStoreError> {
            tokio::time::sleep(IDLE_ROUND_TRIP).await;
            self.general_claims.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
        async fn claim_small(&self, _: &str, _: Duration)
            -> std::result::Result<Option<nanosiem_core::search::job_runner_store::RunnerClaim>, DurableJobStoreError> {
            tokio::time::sleep(IDLE_ROUND_TRIP).await;
            self.small_claims.fetch_add(1, Ordering::Relaxed);
            if self.small_refused {
                return Err(DurableJobStoreError::Unavailable(
                    "hosted coordinator refused claim with status 409 code invalid_command".into(),
                ));
            }
            Ok(None)
        }
        async fn renew(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: Duration)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn progress(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &nanosiem_core::search::SearchJobProgress)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn complete(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &nanosiem_core::search::SearchJobResultRef)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn fail(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim, _: &str, _: bool, _: bool, _: u32)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
        async fn cancel_claim(&self, _: &nanosiem_core::search::job_runner_store::RunnerClaim)
            -> std::result::Result<bool, DurableJobStoreError> { unreachable!("idle") }
    }

    /// NAN-4290 CF cost: an idle tenant's small slot sends no coordinator
    /// request (an idle general slot takes any queued job, small ones too).
    /// While a general slot runs a job, the small slot polls the small lane
    /// at the same ≤ 1/s backoff; once the job ends it stops again.
    #[tokio::test(start_paused = true)]
    async fn the_small_slot_polls_only_while_a_general_slot_holds_a_job() {
        let directory = tempfile::tempdir().unwrap();
        let arguments = runner_arguments(&directory, &[]).unwrap();
        let store = LaneCoordinator::default();
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let slots = async {
            tokio::join!(
                runner_loop(&store, &arguments, None, &control, SlotLane::General),
                runner_loop(&store, &arguments, None, &control, SlotLane::Small),
            )
        };
        tokio::pin!(slots);
        macro_rules! run_for {
            ($slots:expr, $span:expr) => {
                assert!(tokio::time::timeout($span, $slots).await.is_err(), "slots keep serving")
            };
        }
        // An idle hour: the general slot polls, the small slot never does.
        run_for!(slots.as_mut(), IDLE_HOUR);
        assert!(store.general_claims.load(Ordering::Relaxed) >= 3_300);
        assert_eq!(store.small_claims.load(Ordering::Relaxed), 0, "an idle small slot costs no request");
        // A general slot runs a 10 min job: the small lane is polled.
        let busy = control.general_claim();
        run_for!(slots.as_mut(), Duration::from_secs(600));
        let polled = store.small_claims.load(Ordering::Relaxed);
        assert!((300..=600).contains(&polled), "{polled} small-lane claims in 10 min (≤ 1/s)");
        // The job ends: the small slot stops polling within one backoff.
        drop(busy);
        run_for!(slots.as_mut(), Duration::from_secs(5));
        let after = store.small_claims.load(Ordering::Relaxed);
        run_for!(slots.as_mut(), Duration::from_secs(600));
        assert_eq!(store.small_claims.load(Ordering::Relaxed), after, "no small-lane request once the general slot is idle");
        // A shutdown signal ends both slots.
        control.begin_drain();
        let (general, small) = tokio::time::timeout(Duration::from_secs(5), slots).await.unwrap();
        general.unwrap();
        small.unwrap();
    }

    /// NAN-4290: a coordinator that predates the lane refuses the `lane`
    /// field. The small slot sits out instead of hammering it; the general
    /// slot keeps running every job as before.
    #[tokio::test(start_paused = true)]
    async fn a_coordinator_without_lanes_parks_the_small_slot() {
        let directory = tempfile::tempdir().unwrap();
        let arguments = runner_arguments(&directory, &[]).unwrap();
        let store = LaneCoordinator { small_refused: true, ..Default::default() };
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let _busy = control.general_claim();
        let small = runner_loop(&store, &arguments, None, &control, SlotLane::Small);
        assert!(tokio::time::timeout(Duration::from_secs(1_800), small).await.is_err());
        let refused = store.small_claims.load(Ordering::Relaxed);
        assert!((1..=4).contains(&refused), "{refused} refused claims in 30 min: parked {SMALL_LANE_UNSUPPORTED_PARK:?} each");
        assert!(small_lane_refused(&Err(DurableJobStoreError::Unsupported)));
        assert!(!small_lane_refused(&Err(DurableJobStoreError::Unavailable("connection reset".into()))));
        assert!(!small_lane_refused(&Ok(None)));
    }

    #[test]
    fn small_lane_slots_need_the_hosted_coordinator() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(runner_arguments(&directory, &[]).unwrap().small_lane_slots, 0, "off unless rendered");
        let error = runner_arguments(&directory, &["--small-lane-slots", "1"]).unwrap_err();
        assert!(error.to_string().contains("--small-lane-slots requires --hosted-coordinator-config"), "{error:#}");
        assert!(runner_arguments(&directory, &["--small-lane-slots", "5"]).is_err());
    }

    #[test]
    fn retry_configuration_rejects_a_placebo_large_class() {
        let directory = tempfile::tempdir().unwrap();
        let error = runner_arguments(
            &directory,
            &["--max-attempts", "2", "--medium-scan-bytes", "2147483648", "--large-scan-bytes", "2147483648"],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("large resource class must exceed the medium"),
            "{error:#}"
        );
    }

    /// A parseable runner: the trusted-local cell-only shape (no hosted
    /// coordinator or DEPLOYMENT_MODE needed).
    fn runner_arguments(_directory: &tempfile::TempDir, extra: &[&str]) -> Result<Arguments> {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let mut values = vec![
            "--cell-only".to_string(),
            "--trusted-local".to_string(),
            "--redis-url".to_string(),
            "redis://127.0.0.1:6379".to_string(),
            "--tenant-id".to_string(),
            tenant.to_string(),
            "--result-root".to_string(),
            nanosiem_lake_worker::part_query::job_results::job_results_root(tenant),
        ];
        values.extend(extra.iter().map(|value| value.to_string()));
        Arguments::parse(values.into_iter())
    }

    /// Lean-lake: `--cell-only` needs no gen1 worker binary or generation
    /// archive, refuses them if given, and still requires hosted fencing.
    #[test]
    fn cell_only_runner_takes_no_gen1_inputs_and_requires_hosted_fencing() {
        let directory = tempfile::tempdir().unwrap();
        let base = |extra: &[&str]| {
            let mut values = vec![
                "--cell-only".to_string(),
                "--tenant-id".to_string(),
                "tenant-a".to_string(),
                "--redis-url".to_string(),
                "redis://127.0.0.1:6379".to_string(),
                "--result-root".to_string(),
                format!("file://{}", directory.path().join("results").display()),
            ];
            values.extend(extra.iter().map(|value| value.to_string()));
            Arguments::parse(values.into_iter())
        };
        let error = base(&[]).unwrap_err().to_string();
        assert!(error.contains("--cell-only requires --hosted-coordinator-config"), "{error}");
        // NAN-3861: without --cell-only there is no gen1 local executor to fall back to.
        let values = vec![
            "--tenant-id".to_string(),
            "tenant-a".to_string(),
            "--redis-url".to_string(),
            "redis://127.0.0.1:6379".to_string(),
            "--result-root".to_string(),
            format!("file://{}", directory.path().join("results").display()),
        ];
        let error = Arguments::parse(values.into_iter()).unwrap_err().to_string();
        assert!(error.contains("requires --cell-only"), "{error}");
        let worker = std::env::current_exe().unwrap().display().to_string();
        let error = base(&["--worker-binary", &worker]).unwrap_err().to_string();
        assert!(error.contains("drop --worker-binary"), "{error}");
        let root = directory.path().display().to_string();
        let error = base(&["--generation-config-root", &root]).unwrap_err().to_string();
        assert!(error.contains("drop --worker-binary"), "{error}");
        // Hosted fencing stays enterprise-shared only, cell-only or not.
        let error = base(&["--hosted-coordinator-config", "/private/config.json"]).unwrap_err().to_string();
        assert!(error.contains("requires enterprise_shared mode"), "{error}");
    }

    #[test]
    fn cell_trusted_local_runner_is_uuid_scoped_and_has_no_gen1_paths() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let base = vec!["--cell-only".into(), "--trusted-local".into(), "--tenant-id".into(), tenant.into(),
            "--redis-url".into(), "redis://127.0.0.1:6379".into(), "--result-root".into(),
            nanosiem_lake_worker::part_query::job_results::job_results_root(tenant)];
        let arguments = Arguments::parse(base.clone().into_iter()).unwrap();
        assert!(arguments.trusted_local && arguments.cell_only);
        assert!(matches!(arguments.tenant_scope, SearchTenantScope::Dedicated));
        let mut foreign = base.clone(); foreign[4] = "default".into();
        assert!(Arguments::parse(foreign.into_iter()).is_err());
        let mut wrong_root = base.clone(); *wrong_root.last_mut().unwrap() = "file:///tmp/results".into();
        assert!(Arguments::parse(wrong_root.into_iter()).is_err());
        let mut gen1 = base; gen1.remove(0);
        assert!(Arguments::parse(gen1.into_iter()).is_err());
    }

    #[test]
    fn cell_trusted_local_route_accepts_compose_and_rejects_foreign_tenants() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let args = Arguments::parse(vec!["--cell-only".into(), "--trusted-local".into(), "--tenant-id".into(), tenant.into(),
            "--redis-url".into(), "redis://127.0.0.1:6379".into(), "--result-root".into(),
            nanosiem_lake_worker::part_query::job_results::job_results_root(tenant)].into_iter()).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({tenant:"http://lake-cell:8790"})).unwrap();
        let token = std::path::Path::new("/sealed/router.token");
        let (hosted, _) = nanosiem_core::search::LakeCellRoutes::parse(&bytes, token).unwrap();
        assert!(hosted.is_empty(), "hosted origin admission remains strict");
        let route = std::sync::Arc::new(LakeCellRoute {
            tenant_id: Uuid::parse_str(tenant).unwrap(), assignment_generation: 1,
            part_log_writer_epoch: 1, worker_revision: 1, assignment_fenced: false,
            cell_origin: "http://lake-cell:8790".into(),
            query_base_url: format!("http://lake-cell:8790/v1/tenants/{tenant}/query"),
            router_token_file: token.into(),
        });
        assert!(validate_trusted_local_cell_route(&args, route.clone()).is_ok());
        let mut foreign = (*route).clone(); foreign.tenant_id = Uuid::new_v4();
        assert!(validate_trusted_local_cell_route(&args, std::sync::Arc::new(foreign)).is_err());
    }

    #[test]
    fn cell_only_requires_both_cell_route_inputs() {
        assert!(require_cell_route_env(Some("/r/routes.json"), Some("/t/router.token")).is_ok());
        assert!(require_cell_route_env(Some("/r/routes.json"), None).is_err());
        assert!(require_cell_route_env(None, Some("/t/router.token")).is_err());
        assert!(require_cell_route_env(Some(" "), Some("/t/router.token")).is_err());
        assert!(require_cell_route_env(None, None).is_err());
    }

    /// Every phase a cell attempt reports must be one the hosted coordinator
    /// accepts; "cell_dispatched" was refused with 409 `invalid_phase` and
    /// every lean async search died on lease expiry.
    #[test]
    fn cell_attempt_phases_are_in_the_coordinator_allowlist() {
        use nanosiem_core::search::job_coordinator_client::HOSTED_PROGRESS_PHASES;
        assert!(HOSTED_PROGRESS_PHASES.contains(&CELL_DISPATCH_PHASE));
        assert!(HOSTED_PROGRESS_PHASES.contains(&"publishing_result"));
    }

    /// A cell-only claim without a current route is handed back (bounded by
    /// the pin-bounce window), never run on the absent gen1 executor.
    #[test]
    fn cell_only_claim_without_a_route_is_handed_back_not_run_locally() {
        let directory = tempfile::tempdir().unwrap();
        let mut arguments = runner_arguments(&directory, &[]).unwrap();
        assert!(arguments.cell_only);
        arguments.cell_only = false;
        assert_eq!(cell_only_without_route(&arguments), None);
        arguments.cell_only = true;
        assert!(matches!(
            cell_only_without_route(&arguments),
            Some(ClaimOutcome::PinUnavailable(reason)) if reason.contains("no current lean cell route")
        ));
    }

    /// The lean cell image build probes `lake_job_runner --help` for this line.
    #[test]
    fn usage_names_the_binary_and_cell_only_mode() {
        assert!(USAGE.starts_with("usage: lake_job_runner "));
        assert!(USAGE.contains("--cell-only"));
    }
}

/// NAN-2653: zero-downtime reader rolls. Pins archived on a peer pod are
/// handed back (never fatal), and SIGTERM drains instead of abandoning work.
#[cfg(test)]
mod rolling_drain_tests {
    use super::*;

    fn pin(hot_tail: Option<&str>) -> DurableLakeGenerationPin {
        DurableLakeGenerationPin {
            generation_id: "event-42-aaaaaaaaaaaa".to_string(),
            event_config_sha256: "a".repeat(64),
            snapshot_id: 42,
            iceberg_metadata_location: None,
            compiler_sha256: "b".repeat(64),
            native_artifact_sha256: "c".repeat(64),
            hot_tail_manifest_sha256: hot_tail.map(str::to_string),
            hot_tail_snapshot_id: hot_tail.map(|_| 42),
            hot_tail_id: None,
        }
    }

    #[test]
    fn drain_bound_fits_inside_the_pod_grace_period() {
        // terminationGracePeriodSeconds on the reader pod is 60.
        assert!(Duration::from_secs(MAX_DRAIN_SECONDS) + DRAIN_EXIT_MARGIN < Duration::from_secs(60));
        assert!(DEFAULT_DRAIN_SECONDS <= MAX_DRAIN_SECONDS);
    }

    #[test]
    fn job_scoped_errors_fail_the_job_and_only_store_outages_propagate() {
        // Before NAN-2653 every one of these exited the whole runner process.
        for error in [
            anyhow::anyhow!("shared durable job range expired before execution"),
            anyhow::anyhow!("archived event config differs from the durable admission pin"),
            anyhow::Error::from(std::io::Error::other("disk full")).context("write job spec"),
        ] {
            assert_eq!(classify_claim_error(&error), ClaimErrorAction::FailJob, "{error:#}");
        }
        let store = anyhow::Error::from(DurableJobStoreError::Unavailable("timeout".into()))
            .context("renew");
        assert_eq!(classify_claim_error(&store), ClaimErrorAction::StoreUnavailable);
    }

    #[test]
    fn pin_bounce_backs_off_then_expires_after_the_bound() {
        let bound = Duration::from_secs(60);
        let mut tracker = PinBounceTracker::new(bound);
        let start = Instant::now();
        let backoffs = (0..8)
            .map(|step| match tracker.record("job", start + Duration::from_secs(step)) {
                PinBounceDecision::Release { backoff } => backoff,
                other => panic!("released within the bound, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(backoffs[0], PIN_BOUNCE_BACKOFF_BASE);
        assert_eq!(backoffs[1], PIN_BOUNCE_BACKOFF_BASE * 2);
        assert!(backoffs.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(*backoffs.last().unwrap(), PIN_BOUNCE_BACKOFF_MAX);
        // Other jobs keep their own window.
        assert!(matches!(
            tracker.record("other", start + Duration::from_secs(59)),
            PinBounceDecision::Release { backoff } if backoff == PIN_BOUNCE_BACKOFF_BASE
        ));
        assert_eq!(
            tracker.record("job", start + Duration::from_secs(60)),
            PinBounceDecision::Expire { bounced_for: bound }
        );
        // Expiry forgets the job; a resubmitted job id would start fresh.
        assert!(matches!(
            tracker.record("job", start + Duration::from_secs(61)),
            PinBounceDecision::Release { backoff } if backoff == PIN_BOUNCE_BACKOFF_BASE
        ));
    }

    #[test]
    fn pin_bounce_window_resets_after_the_job_ran_elsewhere() {
        let bound = Duration::from_secs(10);
        let mut tracker = PinBounceTracker::new(bound);
        let start = Instant::now();
        assert!(matches!(tracker.record("job", start), PinBounceDecision::Release { .. }));
        // Not seen for longer than a bound: the peer ran it and the id is
        // back only by coincidence. Never expire on the stale first sighting.
        assert!(matches!(
            tracker.record("job", start + Duration::from_secs(11)),
            PinBounceDecision::Release { backoff } if backoff == PIN_BOUNCE_BACKOFF_BASE
        ));
        tracker.forget("job");
        assert!(tracker.entries.is_empty());
    }

    #[test]
    fn drain_phase_stops_claims_then_expires_in_flight_work() {
        let drain = Duration::from_secs(45);
        let now = Instant::now();
        assert_eq!(drain_phase(None, drain, now), DrainPhase::Running);
        assert_eq!(
            drain_phase(Some(now), drain, now + Duration::from_secs(10)),
            DrainPhase::Draining { remaining: Duration::from_secs(35) }
        );
        assert_eq!(drain_phase(Some(now), drain, now + drain), DrainPhase::Expired);
        assert_eq!(
            drain_phase(Some(now), drain, now + Duration::from_secs(600)),
            DrainPhase::Expired
        );
        // A clock that reads earlier than the signal is still draining.
        assert_eq!(
            drain_phase(Some(now + Duration::from_secs(1)), drain, now),
            DrainPhase::Draining { remaining: drain }
        );
    }

    #[tokio::test]
    async fn runner_control_drains_once_and_wakes_sleepers() {
        let control = std::sync::Arc::new(RunnerControl::new(
            Duration::from_millis(100),
            Duration::from_secs(60),
        ));
        assert!(!control.draining());
        let sleeper = {
            let control = control.clone();
            tokio::spawn(async move {
                let started = Instant::now();
                control.sleep(Duration::from_secs(30)).await;
                started.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(control.begin_drain());
        assert!(!control.begin_drain(), "a second signal does not restart the clock");
        assert!(control.draining());
        let slept = tokio::time::timeout(Duration::from_secs(2), sleeper)
            .await
            .expect("signal cuts poll/backoff sleeps short")
            .unwrap();
        assert!(slept < Duration::from_secs(2));
        tokio::time::timeout(Duration::from_secs(2), control.drain_expired())
            .await
            .expect("drain bound elapses");
        assert_eq!(control.phase(), DrainPhase::Expired);
    }

    #[test]
    fn drain_and_bounce_settings_are_bounded() {
        assert_eq!(parse_seconds_setting(None, "K", 45, 1, 50).unwrap(), 45);
        assert_eq!(parse_seconds_setting(Some(" ".into()), "K", 45, 1, 50).unwrap(), 45);
        assert_eq!(parse_seconds_setting(Some("30".into()), "K", 45, 1, 50).unwrap(), 30);
        for invalid in ["0", "51", "60", "-1", "45s"] {
            assert!(
                parse_seconds_setting(Some(invalid.into()), "K", 45, 1, 50).is_err(),
                "{invalid}"
            );
        }
        let arguments = |extra: &[&str]| {
            let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
            let mut values = vec![
                "--cell-only".to_string(),
                "--trusted-local".to_string(),
                "--redis-url".to_string(),
                "redis://127.0.0.1:6379".to_string(),
                "--tenant-id".to_string(),
                tenant.to_string(),
                "--result-root".to_string(),
                nanosiem_lake_worker::part_query::job_results::job_results_root(tenant),
                "--max-attempts".to_string(),
                "1".to_string(),
            ];
            values.extend(extra.iter().map(|value| value.to_string()));
            Arguments::parse(values.into_iter())
        };
        if std::env::var_os(DRAIN_SECONDS_ENV).is_none()
            && std::env::var_os(PIN_BOUNCE_SECONDS_ENV).is_none()
        {
            let defaults = arguments(&[]).unwrap();
            assert_eq!(defaults.drain, Duration::from_secs(DEFAULT_DRAIN_SECONDS));
            assert_eq!(defaults.pin_bounce_bound, Duration::from_secs(DEFAULT_PIN_BOUNCE_SECONDS));
        }
        let custom = arguments(&["--drain-seconds", "20", "--pin-bounce-seconds", "90"]).unwrap();
        assert_eq!(custom.drain, Duration::from_secs(20));
        assert_eq!(custom.pin_bounce_bound, Duration::from_secs(90));
        assert!(arguments(&["--drain-seconds", "59"]).is_err());
        assert!(arguments(&["--pin-bounce-seconds", "1"]).is_err());
    }

    fn redis_arguments(_directory: &tempfile::TempDir, redis_url: &str) -> Arguments {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        Arguments::parse(
            [
                "--cell-only".to_string(),
                "--trusted-local".to_string(),
                "--redis-url".to_string(),
                redis_url.to_string(),
                "--tenant-id".to_string(),
                tenant.to_string(),
                "--result-root".to_string(),
                nanosiem_lake_worker::part_query::job_results::job_results_root(tenant),
                "--max-attempts".to_string(),
                "2".to_string(),
                "--large-scan-bytes".to_string(),
                (1_u64 << 40).to_string(),
            ]
            .into_iter(),
        )
        .unwrap()
    }

    // ---- Scripted store: settle_claim verdicts without a live Redis. ----

    #[derive(Debug, Clone, Copy)]
    enum Scripted {
        Changed(bool),
        Unavailable,
        Invalid,
        ClaimRejected,
        Unsupported,
    }

    impl Scripted {
        fn result(self) -> std::result::Result<bool, DurableJobStoreError> {
            match self {
                Scripted::Changed(changed) => Ok(changed),
                Scripted::Unavailable => Err(DurableJobStoreError::Unavailable("down".into())),
                Scripted::Invalid => Err(DurableJobStoreError::Invalid("bad".into())),
                Scripted::ClaimRejected => Err(DurableJobStoreError::ClaimRejected),
                Scripted::Unsupported => Err(DurableJobStoreError::Unsupported),
            }
        }
    }

    #[derive(Debug, Default)]
    struct ScriptedStore {
        /// NAN-4290: claims cover the last hour (a small-lane job).
        small: std::sync::atomic::AtomicBool,
        inner: nanosiem_core::search::InMemoryJobStore,
        release: std::sync::Mutex<std::collections::VecDeque<Scripted>>,
        fail: std::sync::Mutex<std::collections::VecDeque<Scripted>>,
        /// "release" or "fail:<retryable>:<error>" per store call, in order.
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl ScriptedStore {
        fn script_release(&self, steps: &[Scripted]) {
            self.release.lock().unwrap().extend(steps.iter().copied());
        }
        fn script_fail(&self, steps: &[Scripted]) {
            self.fail.lock().unwrap().extend(steps.iter().copied());
        }
        fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
        async fn runner_claim(&self) -> nanosiem_core::search::job_runner_store::RunnerClaim {
            use nanosiem_core::search::job_runner_store::DurableJobRunnerStore;
            DurableJobRunnerStore::claim(self, "owner-1", Duration::from_secs(30))
                .await
                .unwrap()
                .unwrap()
        }
    }

    #[async_trait::async_trait]
    impl nanosiem_core::search::SearchJobStore for ScriptedStore {
        async fn create(
            &self,
            request: nanosiem_core::search::SearchRequest,
            scope: &nanosiem_core::auth::ScopeSet,
        ) -> Option<String> {
            self.inner.create(request, scope).await
        }
        async fn create_queued(
            &self,
            request: nanosiem_core::search::SearchRequest,
            user_id: Uuid,
            priority: nanosiem_core::search::QueryPriority,
            scope: &nanosiem_core::auth::ScopeSet,
        ) -> Option<String> {
            self.inner.create_queued(request, user_id, priority, scope).await
        }
        async fn claim_durable(
            &self,
            worker_id: &str,
            _lease: Duration,
        ) -> std::result::Result<Option<DurableSearchJobClaim>, DurableJobStoreError> {
            let end = Utc::now();
            let start = if self.small.load(Ordering::SeqCst) { end - chrono::Duration::hours(1) } else { end };
            let request = serde_json::from_value(serde_json::json!({
                "query":"* | stats count", "time_range":{"start":start,"end":end},
                "skip_histogram":false,"skip_field_stats":false,"use_cache":false,"table_view":false,"async_mode":true
            }))
            .unwrap();
            Ok(Some(DurableSearchJobClaim {
                job_id: "job-1".to_string(),
                tenant_id: None,
                attempt: 1,
                fence: 1,
                lease_owner: worker_id.to_string(),
                lease_expires_at_ms: Utc::now().timestamp_millis() + 30_000,
                request,
                user_id: Uuid::nil(),
                priority: nanosiem_core::search::QueryPriority::Analytics,
                scope_deny: Default::default(),
                scope_artifact_deny: Default::default(),
                authority: None,
                generation_pin: pin(None),
                task: nanosiem_core::search::DurableLakeTask::SearchNplV1,
                resource_class: DurableQueryResourceClass::Medium,
            }))
        }
        async fn fail_durable_attempt(
            &self,
            _job_id: &str,
            _worker_id: &str,
            _attempt: u32,
            _fence: u64,
            error: &str,
            retryable: bool,
            promote_resource_class: bool,
            _max_attempts: u32,
        ) -> std::result::Result<bool, DurableJobStoreError> {
            let promote = if promote_resource_class { "promote:" } else { "" };
            self.calls.lock().unwrap().push(format!("fail:{retryable}:{promote}{error}"));
            self.fail.lock().unwrap().pop_front().unwrap_or(Scripted::Changed(true)).result()
        }
        async fn release_durable_claim(
            &self,
            _job_id: &str,
            _worker_id: &str,
            _attempt: u32,
            _fence: u64,
        ) -> std::result::Result<bool, DurableJobStoreError> {
            self.calls.lock().unwrap().push("release".to_string());
            self.release.lock().unwrap().pop_front().unwrap_or(Scripted::Changed(true)).result()
        }
        async fn get(&self, job_id: &str) -> Option<nanosiem_core::search::SearchJob> {
            self.inner.get(job_id).await
        }
        async fn get_status(
            &self,
            job_id: &str,
        ) -> Option<nanosiem_core::search::SearchJobStatusResponse> {
            self.inner.get_status(job_id).await
        }
        async fn get_query_id(&self, job_id: &str) -> Option<String> {
            self.inner.get_query_id(job_id).await
        }
        async fn set_query_id(&self, job_id: &str, query_id: String) {
            self.inner.set_query_id(job_id, query_id).await
        }
        async fn complete(&self, job_id: &str, result: nanosiem_core::search::SearchResponse) {
            nanosiem_core::search::SearchJobStore::complete(&self.inner, job_id, result).await
        }
        async fn fail(&self, job_id: &str, error: String) {
            nanosiem_core::search::SearchJobStore::fail(&self.inner, job_id, error).await
        }
        async fn cancel(&self, job_id: &str) {
            self.inner.cancel(job_id).await
        }
        async fn start(&self, job_id: &str) {
            self.inner.start(job_id).await
        }
        async fn remove(&self, job_id: &str) -> Option<nanosiem_core::search::SearchJob> {
            self.inner.remove(job_id).await
        }
        async fn set_queue_position(&self, job_id: &str, position: u32) {
            self.inner.set_queue_position(job_id, position).await
        }
        async fn list_for_user(&self, user_id: Uuid) -> Vec<nanosiem_core::search::SearchJobSummary> {
            self.inner.list_for_user(user_id).await
        }
        async fn list_all(
            &self,
            viewer_deny: &std::collections::BTreeSet<String>,
        ) -> Vec<nanosiem_core::search::AdminSearchJobSummary> {
            self.inner.list_all(viewer_deny).await
        }
        async fn active_count(&self) -> usize {
            self.inner.active_count().await
        }
        async fn total_count(&self) -> usize {
            self.inner.total_count().await
        }
    }

    fn settle_arguments(directory: &tempfile::TempDir) -> Arguments {
        redis_arguments(directory, "redis://127.0.0.1:6379")
    }

    /// NAN-3911: a memory-limit or scan-capacity refusal fails the job once,
    /// non-retryable, with the static `query_too_large` category; any other
    /// attempt failure keeps the generic retryable path.
    #[tokio::test]
    async fn query_too_large_fails_once_without_retry() {
        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;

        let memory = anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE))
            .context("cell job returned HTTP 503 (query_budget_exhausted): query memory budget exceeded");
        settle_claim(&store, &arguments, &claim, Err(memory), &control).await.unwrap();
        assert_eq!(
            store.take_calls(),
            vec![format!("fail:false:{}", nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE)]
        );

        let scan: anyhow::Error = select_resource_class(DurableQueryResourceClass::Large, 9 << 30, 1 << 30, 8 << 30)
            .map_err(QueryTooLarge)
            .unwrap_err()
            .into();
        settle_claim(&store, &arguments, &claim, Err(scan), &control).await.unwrap();
        assert_eq!(store.take_calls(), vec![format!("fail:false:{SCAN_CAPACITY_REASON}")]);

        // Deterministic job shape, not a sick runner: never trips the breaker.
        for _ in 0..MAX_CONSECUTIVE_JOB_FAILURES + 1 {
            let error = anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE));
            settle_claim(&store, &arguments, &claim, Err(error), &control).await.unwrap();
        }
        assert!(!control.draining(), "query_too_large must not trip the circuit breaker");
        store.take_calls();

        settle_claim(&store, &arguments, &claim, Err(anyhow::anyhow!("cell search job returned HTTP 500")), &control)
            .await
            .unwrap();
        assert_eq!(store.take_calls(), vec![format!("fail:true:{RUNNER_ATTEMPT_FAILURE_REASON}")]);
    }

    /// NAN-4277 (F18): a statement timeout is the job's shape: classified
    /// from the cell's error exactly as production logged it, and settled
    /// once, non-retryable, with the time-limit category.
    #[tokio::test]
    async fn a_cell_statement_timeout_fails_once_with_the_time_limit_category() {
        let status = |code| reqwest::StatusCode::from_u16(code).unwrap();
        let logged = "native chDB query failed: chDB query failed: Code: 159. DB::Exception: Timeout exceeded: elapsed 120010.416 ms, maximum: 120000 ms. (TIMEOUT_EXCEEDED)";
        assert!(cell_statement_timed_out(status(500), Some(logged)));
        assert!(!cell_statement_timed_out(status(500), Some("cell search job failed")));
        assert!(!cell_statement_timed_out(status(500), None));
        assert!(!cell_statement_timed_out(status(429), Some(logged)), "a busy refusal is not the statement");

        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;
        let timeout = anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_TIME_MESSAGE))
            .context(format!("cell job returned HTTP 500 (statement time limit): {logged}"));
        settle_claim(&store, &arguments, &claim, Err(timeout), &control).await.unwrap();
        assert_eq!(
            store.take_calls(),
            vec![format!("fail:false:{}", nanosiem_core::search::QUERY_TOO_LARGE_TIME_MESSAGE)]
        );
    }

    /// NAN-4290: a small-lane job that ran out of a small lane's memory is
    /// requeued once as large (the general lane's memory) instead of failed;
    /// a large or long-window job's memory refusal still fails once.
    #[tokio::test]
    async fn a_small_lane_memory_refusal_is_promoted_once() {
        let store = ScriptedStore::default();
        store.small.store(true, Ordering::SeqCst);
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;
        assert!(small_lane_job(&claim));
        let memory = || anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE))
            .context("cell job returned HTTP 503 (query_budget_exhausted): query memory budget exceeded");
        settle_claim(&store, &arguments, &claim, Err(memory()), &control).await.unwrap();
        assert_eq!(
            store.take_calls(),
            vec![format!("fail:true:promote:{}", nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE)]
        );
        // A statement timeout is not a lane's memory: it still fails once.
        let timeout = anyhow::Error::new(QueryTooLarge(nanosiem_core::search::QUERY_TOO_LARGE_TIME_MESSAGE));
        settle_claim(&store, &arguments, &claim, Err(timeout), &control).await.unwrap();
        assert_eq!(store.take_calls(), vec![format!("fail:false:{}", nanosiem_core::search::QUERY_TOO_LARGE_TIME_MESSAGE)]);
        // A job that is not small (here: an empty window) fails once.
        store.small.store(false, Ordering::SeqCst);
        let claim = store.runner_claim().await;
        assert!(!small_lane_job(&claim));
        settle_claim(&store, &arguments, &claim, Err(memory()), &control).await.unwrap();
        assert_eq!(store.take_calls(), vec![format!("fail:false:{}", nanosiem_core::search::QUERY_TOO_LARGE_MEMORY_MESSAGE)]);
    }

    /// NAN-3911: only a per-query memory refusal is deterministic.
    #[test]
    fn cell_memory_refusal_classification() {
        let status = |code| reqwest::StatusCode::from_u16(code).unwrap();
        let budget = Some("query_budget_exhausted");
        assert!(cell_query_too_large(status(503), budget,
            Some("query memory budget exceeded: Code: 241. Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)")));
        assert!(cell_query_too_large(status(503), budget, None));
        // Engine-wide total: concurrent work, may pass on a retry.
        assert!(!cell_query_too_large(status(503), budget,
            Some("query memory budget exceeded: Code: 241. DB::Exception: (total) memory limit exceeded")));
        // Concurrency (429) and other 503s are not too-large.
        assert!(!cell_query_too_large(status(429), budget, None));
        assert!(!cell_query_too_large(status(503), Some("cold_fetch_timeout"), None));
        assert!(!cell_query_too_large(status(503), Some("not_ready"), None));
    }

    /// Item: a drain that interrupts a running child is charged (retryable
    /// fail), while one that caught the attempt before spawn is free.
    #[tokio::test]
    async fn drain_hand_back_is_free_only_before_the_child_started() {
        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;

        settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::Drained), &control)
            .await
            .unwrap();
        assert_eq!(store.take_calls(), vec!["release".to_string()]);

        settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::DrainInterrupted), &control)
            .await
            .unwrap();
        assert_eq!(
            store.take_calls(),
            vec![format!("fail:true:{RUNNER_DRAIN_INTERRUPTED_REASON}")],
            "a killed running child must spend budget, never a free release"
        );
        // A store outage still surfaces (the runner loop backs off).
        store.script_fail(&[Scripted::Unavailable]);
        assert!(settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::DrainInterrupted), &control)
            .await
            .is_err());
    }

    /// Item: the child's structured pin-mismatch line becomes a hand-back.
    #[test]
    fn pin_mismatch_is_read_from_the_structured_child_line() {
        let line = nanosiem_lake_worker::job::pin_mismatch_line();
        assert!(nanosiem_lake_worker::job::stdout_reports_pin_mismatch(
            format!("{{\"durable_phase\":\"hydrating_tail\"}}\n{line}\n").as_bytes()
        ));
        assert!(!nanosiem_lake_worker::job::stdout_reports_pin_mismatch(
            b"job execution generation differs from its immutable admission pin"
        ));
    }

    /// Item: hand-back/expire store refusals other than Unavailable are
    /// scoped to the attempt; only Unavailable propagates.
    #[tokio::test]
    async fn hand_back_refusals_are_logged_not_fatal() {
        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;
        for refusal in [Scripted::Invalid, Scripted::ClaimRejected] {
            store.script_release(&[refusal]);
            settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::Drained), &control)
                .await
                .unwrap_or_else(|error| panic!("{refusal:?} must not exit the runner: {error:#}"));
        }
        // Unsupported falls back to a retryable fail; its refusal is not fatal either.
        store.take_calls();
        store.script_release(&[Scripted::Unsupported]);
        store.script_fail(&[Scripted::Invalid]);
        settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::Drained), &control)
            .await
            .unwrap();
        assert_eq!(
            store.take_calls(),
            vec!["release".to_string(), format!("fail:true:{RUNNER_RELEASE_REASON}")]
        );
        store.script_release(&[Scripted::Unavailable]);
        assert!(settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::Drained), &control)
            .await
            .is_err());

        // Expire path (bound zero: the first bounce expires).
        let expiring = RunnerControl::new(Duration::from_secs(45), Duration::ZERO);
        for refusal in [Scripted::Invalid, Scripted::ClaimRejected, Scripted::Unsupported] {
            store.script_fail(&[refusal]);
            settle_claim(
                &store,
                &arguments,
                &claim,
                Ok(ClaimOutcome::PinUnavailable("peer".into())),
                &expiring,
            )
            .await
            .unwrap_or_else(|error| panic!("{refusal:?} must not exit the runner: {error:#}"));
        }
        store.script_fail(&[Scripted::Unavailable]);
        assert!(settle_claim(
            &store,
            &arguments,
            &claim,
            Ok(ClaimOutcome::PinUnavailable("peer".into())),
            &expiring,
        )
        .await
        .is_err());
    }

    /// Item: consecutive runner-side failures trip a breaker that drains the
    /// runner (no new claims) and makes `main` exit non-zero; any settled
    /// attempt resets the streak.
    #[tokio::test]
    async fn consecutive_runner_side_failures_trip_the_circuit_breaker() {
        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), Duration::from_secs(60));
        let claim = store.runner_claim().await;
        let job_error = || Err(anyhow::anyhow!("create isolated job directory: disk full"));
        for _ in 0..MAX_CONSECUTIVE_JOB_FAILURES - 1 {
            settle_claim(&store, &arguments, &claim, job_error(), &control).await.unwrap();
        }
        assert!(!control.tripped() && !control.draining());
        // One healthy attempt resets the streak.
        settle_claim(&store, &arguments, &claim, Ok(ClaimOutcome::Finished), &control)
            .await
            .unwrap();
        for _ in 0..MAX_CONSECUTIVE_JOB_FAILURES - 1 {
            settle_claim(&store, &arguments, &claim, job_error(), &control).await.unwrap();
        }
        assert!(!control.tripped());
        settle_claim(&store, &arguments, &claim, job_error(), &control).await.unwrap();
        assert!(control.tripped(), "the fifth consecutive failure trips the breaker");
        assert!(control.draining(), "a tripped runner claims nothing new");
        let fails = store
            .take_calls()
            .into_iter()
            .filter(|call| call.starts_with("fail:true:"))
            .count();
        assert_eq!(fails as u32, 2 * MAX_CONSECUTIVE_JOB_FAILURES - 1);
    }

    /// Item: every slot of the pod sits out the backoff for a job this pod
    /// just bounced, with a free hand-back and no new bounce recorded.
    #[tokio::test]
    async fn a_just_bounced_job_is_held_off_by_every_slot() {
        let bound = Duration::from_secs(60);
        let mut tracker = PinBounceTracker::new(bound);
        let now = Instant::now();
        assert_eq!(tracker.hold_remaining("job", now), None);
        let PinBounceDecision::Release { backoff } = tracker.record("job", now) else {
            panic!("first bounce releases");
        };
        assert_eq!(tracker.hold_remaining("job", now), Some(backoff));
        assert_eq!(tracker.hold_remaining("other", now), None);
        assert_eq!(tracker.hold_remaining("job", now + backoff), None);

        let store = ScriptedStore::default();
        let directory = tempfile::tempdir().unwrap();
        let arguments = settle_arguments(&directory);
        let control = RunnerControl::new(Duration::from_secs(45), bound);
        let claim = store.runner_claim().await;
        // Slot A bounces the peer's job (and is now sleeping its backoff).
        assert!(matches!(control.record_bounce(&claim.job_id), PinBounceDecision::Release { .. }));
        // Meanwhile slot B claims it again: held, not re-bounced.
        let hold = control.bounce_hold(&claim.job_id).expect("inside the backoff");
        let outcome = run_claim(
            &store,
            &arguments,
            &claim,
            None,
            &control,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ClaimOutcome::BounceHold(remaining) if remaining <= hold));
        let ClaimOutcome::BounceHold(remaining) = outcome else { unreachable!() };
        let started = Instant::now();
        settle_claim(&store, &arguments, &claim, Ok(outcome), &control).await.unwrap();
        assert!(started.elapsed() >= remaining, "slot B sat out the rest of the backoff");
        assert_eq!(store.take_calls(), vec!["release".to_string()]);
        let entries = control.bounces.lock().unwrap();
        assert_eq!(entries.entries["job-1"].count, 1, "a hold records no new bounce");
    }
}

#[cfg(test)]
mod cell_dispatch_tests {
    use super::{cell_attempt_not_started, cell_cold_fetch_timeout, cell_lane_wait_timeout, cold_fetch_backoff, cold_fetch_retry_phase, lane_wait_backoff, COLD_FETCH_MAX_RESENDS, COLD_FETCH_RETRY_BUDGET, LANE_WAIT_RETRY_BUDGET};
    use reqwest::StatusCode;
    use std::time::Duration;

    /// NAN-3272: only the cell's typed lane-wait refusal is re-sent in-claim;
    /// it is not a "never started" hand-back, and an untyped 500 (an older
    /// cell that kept the attempt record) is charged as before.
    #[test]
    fn lane_wait_timeout_is_retried_in_claim_only_when_typed() {
        assert!(cell_lane_wait_timeout(StatusCode::SERVICE_UNAVAILABLE, Some("lane_wait_timeout")));
        assert!(!cell_attempt_not_started(StatusCode::SERVICE_UNAVAILABLE, Some("lane_wait_timeout")));
        assert!(!cell_lane_wait_timeout(StatusCode::INTERNAL_SERVER_ERROR, Some("internal")));
        assert!(!cell_lane_wait_timeout(StatusCode::INTERNAL_SERVER_ERROR, Some("lane_wait_timeout")));
        assert!(!cell_lane_wait_timeout(StatusCode::SERVICE_UNAVAILABLE, Some("not_ready")));
        assert!(!cell_lane_wait_timeout(StatusCode::SERVICE_UNAVAILABLE, None));
    }

    /// NAN-3272: exponential backoff (5 s doubling, 60 s cap) bounded by a
    /// ten-minute budget: many more than the old two attempts ~20 s apart.
    #[test]
    fn lane_wait_backoff_is_exponential_capped_and_bounded() {
        let first: Vec<_> = (1..=6).map(|retry| lane_wait_backoff(retry, Duration::ZERO).unwrap().as_secs()).collect();
        assert_eq!(first, vec![5, 10, 20, 40, 60, 60]);
        assert_eq!(lane_wait_backoff(u32::MAX, Duration::ZERO), Some(Duration::from_secs(60)));
        // Each lane wait itself costs ~20 s; simulate the whole schedule.
        let lane_wait = Duration::from_secs(20);
        let (mut waited, mut retries) = (lane_wait, 0_u32);
        while let Some(backoff) = lane_wait_backoff(retries + 1, waited) {
            retries += 1;
            waited += backoff + lane_wait;
        }
        assert!(retries >= 6, "only {retries} lane-wait retries");
        assert!(waited <= LANE_WAIT_RETRY_BUDGET + lane_wait, "{waited:?}");
        assert_eq!(lane_wait_backoff(1, LANE_WAIT_RETRY_BUDGET), None);
    }

    #[test]
    fn cold_fetch_timeouts_are_re_sent_with_a_bounded_backoff() {
        assert!(cell_cold_fetch_timeout(StatusCode::SERVICE_UNAVAILABLE, Some("cold_fetch_timeout")));
        assert!(!cell_cold_fetch_timeout(StatusCode::INTERNAL_SERVER_ERROR, Some("internal")));
        assert!(!cell_cold_fetch_timeout(StatusCode::SERVICE_UNAVAILABLE, Some("lane_wait_timeout")));
        let schedule: Vec<_> = (1..=COLD_FETCH_MAX_RESENDS)
            .map(|retry| cold_fetch_backoff(retry, Duration::ZERO).unwrap().as_secs()).collect();
        assert_eq!(schedule, vec![10, 20, 40, 60]);
        // Five sends in all, never a sixth.
        assert_eq!(cold_fetch_backoff(COLD_FETCH_MAX_RESENDS + 1, Duration::ZERO), None);
        assert_eq!(cold_fetch_backoff(0, Duration::ZERO), None);
        // And never past the time budget.
        assert_eq!(cold_fetch_backoff(1, COLD_FETCH_RETRY_BUDGET), None);
        assert_eq!(cold_fetch_backoff(2, COLD_FETCH_RETRY_BUDGET - Duration::from_secs(19)), None);
        // Every retry phase is one the hosted coordinator accepts.
        for retry in 1..=COLD_FETCH_MAX_RESENDS {
            assert!(nanosiem_core::search::job_coordinator_client::HOSTED_PROGRESS_PHASES
                .contains(&cold_fetch_retry_phase(retry)), "{retry}");
        }
    }

    #[test]
    fn busy_or_waking_cell_hands_the_job_back_uncharged() {
        assert!(cell_attempt_not_started(StatusCode::TOO_MANY_REQUESTS, Some("job_busy")));
        assert!(cell_attempt_not_started(StatusCode::SERVICE_UNAVAILABLE, Some("not_ready")));
        // Misconfiguration or a real failure is charged to the job.
        assert!(!cell_attempt_not_started(StatusCode::SERVICE_UNAVAILABLE, Some("result_storage_unavailable")));
        assert!(!cell_attempt_not_started(StatusCode::CONFLICT, Some("stale_job_pin")));
        assert!(!cell_attempt_not_started(StatusCode::TOO_MANY_REQUESTS, None));
    }
}

#[cfg(test)]
mod cell_job_signature_tests {
    use super::*;
    use nanosiem_lake_cell::tenant_token::{TenantKey, TenantScope};

    /// NAN-3289 P2-2: the runner signs the exact dispatched bytes with its
    /// tenant's `job` key for the route's cell, and the router's verifier
    /// accepts exactly that (and nothing for another tenant).
    #[test]
    fn runner_signatures_verify_at_the_router() {
        let tenant = "0b7a2f9e-1c4d-4e8f-9a0b-1c2d3e4f5a6b";
        let routes = format!(r#"{{"{tenant}": "http://nano-cell-c1.nano-lake-cells.svc:8790"}}"#);
        let (routes, rejected) = nanosiem_core::search::LakeCellRoutes::parse(routes.as_bytes(),
            std::path::Path::new("/run/router.token")).unwrap();
        assert!(rejected.is_empty());
        let route = routes.route(Uuid::parse_str(tenant).unwrap()).unwrap();
        let key = TenantKey::from_router_token("full-router-token-0123456789abcdef0123456789");
        let job_key = key.token(tenant, "c1", TenantScope::Job);
        let body = br#"{"tenant_id":"t"}"#;
        let signature = sign_cell_job_spec(route, &job_key, body).unwrap();
        assert!(key.verify_job_spec(tenant, "c1", body, &signature));
        assert!(!key.verify_job_spec("6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00", "c1", body, &signature));
        // An origin with no cell id cannot be signed for.
        let (other, _) = nanosiem_core::search::LakeCellRoutes::parse(
            format!(r#"{{"{tenant}": "http://10.1.2.3:8790"}}"#).as_bytes(), std::path::Path::new("/run/router.token")).unwrap();
        assert!(sign_cell_job_spec(other.route(Uuid::parse_str(tenant).unwrap()).unwrap(), &job_key, body).is_err());
    }
}
