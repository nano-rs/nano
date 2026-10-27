// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed hosted durable-job operations. Factory selection and public polling
//! are separate integration gates; this client never initializes storage.
use std::{sync::Arc, time::Duration};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    job_coordinator_transport::{
        CoordinatorFailure, CoordinatorTransportError, HostedCoordinatorTransport,
    },
    job_envelope::{
        decode_hosted_claim, decode_hosted_job, encode_hosted_job, HostedClaimContext,
        HostedClaimLease, HostedJobSubmission,
    },
    job_signing::{DurableJobEnvelope, DurableJobSigningKey},
    jobs::{
        DurableJobStoreError, DurableQueryResourceClass, DurableSearchJobClaim, SearchJob,
        SearchJobBackend, SearchJobResultRef, SearchJobStatus,
    },
    tenant::SearchTenantScope,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// The coordinator Worker's closed `progress.phase` allowlist
/// (`enterprise/cloudflare/job-coordinator/contract.mjs`). Any other
/// phase is a 409 `invalid_phase` there, so it is refused here before the
/// network round trip instead of surfacing as a store outage.
///
/// NAN-3883: `retrying_<n>` is the runner's n-th re-send of a durable
/// attempt after a cold-fetch timeout (the UI shows "retrying (n)").
pub const HOSTED_PROGRESS_PHASES: [&str; 8] = [
    "claimed", "hydrating_tail", "scanning", "publishing_result",
    "retrying_1", "retrying_2", "retrying_3", "retrying_4",
];

/// NAN-4290: the coordinator's claim lane for small jobs
/// (`contract.mjs`: `command.lane === 'small'`).
pub const SMALL_LANE: &str = "small";

fn valid_phase(phase: &str) -> bool {
    HOSTED_PROGRESS_PHASES.contains(&phase)
}
use super::job_runner_store::{DurableJobRunnerStore, RunnerClaim};
use super::jobs::SearchJobProgress;

#[async_trait::async_trait]
impl DurableJobRunnerStore for HostedCoordinatorClient {
    async fn reconcile(&self, max_attempts: u32) -> Result<usize, DurableJobStoreError> {
        if max_attempts != self.policy.max_execution_failures {
            return Err(rejected());
        }
        HostedCoordinatorClient::reconcile(self).await
    }
    /// `enterprise/cloudflare/job-coordinator/sqlite-store.mjs`:
    /// `claim` runs `expireBatch(now, policy)` (the `reconcile` sweep) inside
    /// its own transaction before selecting a job. A separate `reconcile` per
    /// idle poll doubled the coordinator request rate (NAN-3559).
    fn claim_recovers_expired_leases(&self) -> bool {
        true
    }
    async fn claim(
        &self,
        owner: &str,
        lease: Duration,
    ) -> Result<Option<RunnerClaim>, DurableJobStoreError> {
        Ok(HostedCoordinatorClient::claim(self, owner, lease)
            .await?
            .map(RunnerClaim::hosted))
    }
    async fn claim_small(
        &self,
        owner: &str,
        lease: Duration,
    ) -> Result<Option<RunnerClaim>, DurableJobStoreError> {
        Ok(HostedCoordinatorClient::claim_lane(self, owner, lease, Some(SMALL_LANE))
            .await?
            .map(RunnerClaim::hosted))
    }
    async fn renew(&self, c: &RunnerClaim, lease: Duration) -> Result<bool, DurableJobStoreError> {
        HostedCoordinatorClient::renew(self, c.hosted_claim()?, lease).await
    }
    async fn progress(
        &self,
        c: &RunnerClaim,
        p: &SearchJobProgress,
    ) -> Result<bool, DurableJobStoreError> {
        let mut command = self.stamp(c.hosted_claim()?, "progress")?;
        command["progress"] = json!(p.percent);
        if let Some(phase) = &p.phase {
            if !valid_phase(phase) {
                return Err(DurableJobStoreError::Invalid(format!(
                    "progress phase {phase:?} is not in the hosted coordinator allowlist"
                )));
            }
            command["phase"] = json!(phase);
        }
        self.boolean(command).await
    }
    async fn complete(
        &self,
        c: &RunnerClaim,
        r: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError> {
        HostedCoordinatorClient::complete(self, c.hosted_claim()?, r).await
    }
    async fn fail(
        &self,
        c: &RunnerClaim,
        error: &str,
        retryable: bool,
        promote: bool,
        max_attempts: u32,
    ) -> Result<bool, DurableJobStoreError> {
        if max_attempts != self.policy.max_execution_failures {
            return Err(rejected());
        }
        let category = published_failure_category(error);
        HostedCoordinatorClient::fail(
            self,
            c.hosted_claim()?,
            retryable,
            promote,
            category,
        )
        .await
    }
    async fn cancel_claim(&self, c: &RunnerClaim) -> Result<bool, DurableJobStoreError> {
        HostedCoordinatorClient::cancel_claim(self, c.hosted_claim()?).await
    }
    async fn release_claim(&self, c: &RunnerClaim) -> Result<bool, DurableJobStoreError> {
        HostedCoordinatorClient::release_claim(self, c.hosted_claim()?).await
    }
}

/// Child stderr can contain raw query/credential data. Publish a static
/// category only; the runner retains detailed diagnostics locally.
fn published_failure_category(error: &str) -> &'static str {
    match error {
        "Search authority temporarily unavailable" => "Search authority temporarily unavailable",
        // NAN-3911: the typed `query_too_large` categories are static runner
        // strings; the job status maps them to an error code.
        super::jobs::QUERY_TOO_LARGE_SCAN_MESSAGE => super::jobs::QUERY_TOO_LARGE_SCAN_MESSAGE,
        super::jobs::QUERY_TOO_LARGE_MEMORY_MESSAGE => super::jobs::QUERY_TOO_LARGE_MEMORY_MESSAGE,
        super::jobs::QUERY_TOO_LARGE_TIME_MESSAGE => super::jobs::QUERY_TOO_LARGE_TIME_MESSAGE,
        // NAN-4277 (F18): chDB's statement time limit is a known cause, not
        // free text: publish its static category, never the message itself.
        raw if raw.contains("TIMEOUT_EXCEEDED") => super::jobs::QUERY_TOO_LARGE_TIME_MESSAGE,
        _ => "isolated query execution failed",
    }
}

#[cfg(test)]
mod published_failure_category_tests {
    use super::*;

    #[test]
    fn query_too_large_categories_survive_and_carry_their_error_code() {
        for message in [
            super::super::jobs::QUERY_TOO_LARGE_MEMORY_MESSAGE,
            super::super::jobs::QUERY_TOO_LARGE_SCAN_MESSAGE,
            super::super::jobs::QUERY_TOO_LARGE_TIME_MESSAGE,
        ] {
            let published = published_failure_category(message);
            assert_eq!(published, message);
            assert!(published.len() <= 256, "the coordinator refuses longer errors");
            assert_eq!(
                super::super::jobs::search_job_error_code(Some(published)).as_deref(),
                Some(super::super::jobs::QUERY_TOO_LARGE_ERROR_CODE)
            );
        }
        // Free text never passes through, and never gains an error code.
        let raw = "cell job returned HTTP 503 (query_budget_exhausted): query memory budget exceeded: SELECT secret";
        assert_eq!(published_failure_category(raw), "isolated query execution failed");
        assert_eq!(super::super::jobs::search_job_error_code(Some(raw)), None);
        assert_eq!(super::super::jobs::search_job_error_code(None), None);
    }

    /// NAN-4277 (F18, a large hosted tenant, 2026-10-20): a 7 d keyword job's
    /// statement timed out twice and the user saw only "isolated query
    /// execution failed". The runner's error (as logged) now publishes the
    /// static time-limit category; none of its text (SQL, paths) passes.
    #[test]
    fn a_statement_timeout_publishes_the_time_limit_category() {
        let raw = "cell job returned HTTP 500 Internal Server Error (internal): native chDB query failed: chDB query failed: Code: 159. DB::Exception: Timeout exceeded: elapsed 120010.416 ms, maximum: 120000 ms. (TIMEOUT_EXCEEDED)";
        let published = published_failure_category(raw);
        assert_eq!(published, super::super::jobs::QUERY_TOO_LARGE_TIME_MESSAGE);
        assert!(!published.contains("chDB") && published.len() <= 256);
        assert_eq!(
            super::super::jobs::search_job_error_code(Some(published)).as_deref(),
            Some(super::super::jobs::QUERY_TOO_LARGE_ERROR_CODE)
        );
    }
}

fn rejected() -> DurableJobStoreError {
    DurableJobStoreError::ClaimRejected
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedCoordinatorRole {
    Producer,
    Runner,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedCoordinatorPolicy {
    pub max_execution_failures: u32,
    pub max_lease_recoveries: u32,
}

/// These are independent authorities: a worker rotation does not imply a plan
/// change, and an entitlement revision does not identify the selected worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedAssignment {
    pub entitlement_revision: i64,
    pub worker_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Description {
    tenant: String,
    epoch: String,
    role: HostedCoordinatorRole,
    policy: HostedCoordinatorPolicy,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PagePosition {
    created: i64,
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePage {
    jobs: Vec<Value>,
    next: Option<PagePosition>,
}
/// Server-side cursor bound to the exact tenant/assignment/retention/epoch.
/// Never accept an untrusted JSON cursor directly as this type.
pub struct HostedJobCursor {
    position: PagePosition,
    binding: String,
}
pub struct HostedJobPage {
    pub jobs: Vec<SearchJob>,
    pub next: Option<HostedJobCursor>,
}

#[derive(Clone)]
enum CoordinatorBackend {
    Hosted(HostedCoordinatorTransport),
    Postgres(Arc<super::job_coordinator_postgres::PostgresJobCoordinator>),
}

#[derive(Clone)]
pub struct HostedCoordinatorClient {
    backend: CoordinatorBackend,
    tenant: SearchTenantScope,
    assignment: HostedAssignment,
    epoch: String,
    role: HostedCoordinatorRole,
    policy: HostedCoordinatorPolicy,
    signer: Arc<DurableJobSigningKey>,
    // Per tenant/assignment client; shared by clones, never a global job cache.
    pub(super) history: Arc<tokio::sync::Mutex<Option<(std::time::Instant, Vec<SearchJob>)>>>,
}
impl std::fmt::Debug for HostedCoordinatorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedCoordinatorClient")
            .finish_non_exhaustive()
    }
}

/// Retain this value across lost submit acknowledgements. Regenerating an ID or
/// timestamp would create a different job, not retry the original submission.
pub struct PreparedHostedJob {
    id: Uuid,
    key: String,
    payload: String,
}
impl PreparedHostedJob {
    pub fn id(&self) -> Uuid {
        self.id
    }
}
impl std::fmt::Debug for PreparedHostedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHostedJob")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub struct HostedClaim {
    claim: DurableSearchJobClaim,
    key: String,
}
impl HostedClaim {
    pub fn claim(&self) -> &DurableSearchJobClaim {
        &self.claim
    }
}
impl std::fmt::Debug for HostedClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedClaim")
            .field("job_id", &self.claim.job_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireJob {
    id: String,
    payload: String,
    status: String,
    created: i64,
    attempt: u32,
    fence: u64,
    owner: Option<String>,
    expires: Option<i64>,
    result: Option<String>,
    #[serde(default)]
    completed: Option<i64>,
    #[serde(default)]
    progress: Option<u32>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    execution_failures: u32,
    #[serde(default)]
    lease_recoveries: u32,
    #[serde(default)]
    resource_class: Option<DurableQueryResourceClass>,
}

impl HostedCoordinatorClient {
    pub(crate) fn tenant_scope(&self) -> SearchTenantScope {
        self.tenant
    }
    pub fn matches_producer_binding(
        &self,
        tenant: SearchTenantScope,
        assignment: HostedAssignment,
    ) -> bool {
        self.role == HostedCoordinatorRole::Producer
            && self.tenant == tenant
            && self.assignment == assignment
    }
    pub async fn connect(
        transport: HostedCoordinatorTransport,
        tenant: SearchTenantScope,
        assignment: HostedAssignment,
        epoch: String,
        role: HostedCoordinatorRole,
        policy: HostedCoordinatorPolicy,
        signer: Arc<DurableJobSigningKey>,
    ) -> Result<Self, DurableJobStoreError> {
        let client = Self::new(transport, tenant, assignment, epoch, role, policy, signer)?;
        client.attest().await?;
        Ok(client)
    }

    fn new(
        transport: HostedCoordinatorTransport,
        tenant: SearchTenantScope,
        assignment: HostedAssignment,
        epoch: String,
        role: HostedCoordinatorRole,
        policy: HostedCoordinatorPolicy,
        signer: Arc<DurableJobSigningKey>,
    ) -> Result<Self, DurableJobStoreError> {
        Self::new_backend(
            CoordinatorBackend::Hosted(transport),
            tenant,
            assignment,
            epoch,
            role,
            policy,
            signer,
        )
    }

    fn new_backend(
        backend: CoordinatorBackend,
        tenant: SearchTenantScope,
        assignment: HostedAssignment,
        epoch: String,
        role: HostedCoordinatorRole,
        policy: HostedCoordinatorPolicy,
        signer: Arc<DurableJobSigningKey>,
    ) -> Result<Self, DurableJobStoreError> {
        tenant
            .require_retention_identity()
            .map_err(|_| rejected())?;
        if tenant.tenant_id() != Some(signer.tenant_id())
            || assignment.entitlement_revision <= 0
            || assignment.worker_revision == 0
            || !valid_id(&epoch)
            || !(1..=10).contains(&policy.max_execution_failures)
            || !(1..=10).contains(&policy.max_lease_recoveries)
        {
            return Err(rejected());
        }
        Ok(Self {
            backend,
            tenant,
            assignment,
            epoch,
            role,
            policy,
            signer,
            history: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub(super) async fn connect_postgres(
        coordinator: Arc<super::job_coordinator_postgres::PostgresJobCoordinator>,
        config: &super::job_coordinator_postgres::PostgresJobConfig,
        role: HostedCoordinatorRole,
        signer: Arc<DurableJobSigningKey>,
    ) -> Result<Self, DurableJobStoreError> {
        let client = Self::new_backend(
            CoordinatorBackend::Postgres(coordinator),
            config.tenant,
            config.assignment,
            config.epoch.clone(),
            role,
            config.policy,
            signer,
        )?;
        client.attest().await?;
        Ok(client)
    }

    /// Sovereign history cache is advisory: its bytes never substitute for a
    /// current grant or a durable namespace read, including during PG outage.
    pub(super) async fn revalidate_history(&self) -> Result<(), DurableJobStoreError> {
        if matches!(&self.backend, CoordinatorBackend::Postgres(_)) {
            self.attest().await?;
        }
        Ok(())
    }

    /// Must pass before runtime startup. Missing storage, wrong token namespace,
    /// role, policy or epoch fails closed; this operation never creates state.
    pub async fn attest(&self) -> Result<(), DurableJobStoreError> {
        let response = self.execute(json!({"op":"describe"})).await?;
        self.validate_description(response)
    }
    fn validate_description(&self, response: Value) -> Result<(), DurableJobStoreError> {
        let observed: Description = serde_json::from_value(response).map_err(|_| rejected())?;
        if observed.tenant != self.signer.tenant_id().to_string()
            || observed.epoch != self.epoch
            || observed.role != self.role
            || observed.policy != self.policy
        {
            return Err(rejected());
        }
        Ok(())
    }

    fn key(&self, id: Uuid) -> Result<String, DurableJobStoreError> {
        if id.is_nil() {
            return Err(rejected());
        }
        let (revision, days, floor) = self
            .tenant
            .require_retention_identity()
            .map_err(|_| rejected())?;
        if let CoordinatorBackend::Postgres(coordinator) = &self.backend {
            return serde_json::to_string(&(
                "nano-sovereign-job-v1",
                coordinator.signing_namespace()?,
                self.signer.tenant_id(),
                revision,
                days,
                floor,
                self.assignment.entitlement_revision,
                self.assignment.worker_revision,
                &self.epoch,
                id,
            ))
            .map_err(|_| rejected());
        }
        serde_json::to_string(&(
            "nano-hosted-job-v2",
            self.signer.tenant_id(),
            revision,
            days,
            floor,
            self.assignment.entitlement_revision,
            self.assignment.worker_revision,
            &self.epoch,
            id,
        ))
        .map_err(|_| rejected())
    }

    pub fn prepare(
        &self,
        id: Uuid,
        submission: HostedJobSubmission<'_>,
    ) -> Result<PreparedHostedJob, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Producer {
            return Err(rejected());
        }
        let key = self.key(id)?;
        let envelope = encode_hosted_job(submission, self.context(id, &key))?;
        let payload = serde_json::to_string(&envelope).map_err(|_| rejected())?;
        Ok(PreparedHostedJob { id, key, payload })
    }

    pub async fn submit(&self, prepared: &PreparedHostedJob) -> Result<Uuid, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Producer || self.key(prepared.id)? != prepared.key {
            return Err(rejected());
        }
        let value = self
            .execute(json!({"op":"submit","job_id":prepared.id,"payload":prepared.payload}))
            .await?;
        self.verify_submission_receipt(prepared, value)
    }

    /// Read back the original signed submission after bounded retries lose their
    /// acknowledgements. Never create a replacement job or accept an ID alone.
    pub async fn recover_submission(
        &self,
        prepared: &PreparedHostedJob,
    ) -> Result<Uuid, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Producer || self.key(prepared.id)? != prepared.key {
            return Err(rejected());
        }
        let value = self
            .execute(json!({"op":"get","job_id":prepared.id}))
            .await?;
        if value.is_null() {
            return Err(DurableJobStoreError::Unavailable(
                "hosted submission acknowledgement remains unavailable".into(),
            ));
        }
        self.verify_submission_receipt(prepared, value)
    }

    fn verify_submission_receipt(
        &self,
        prepared: &PreparedHostedJob,
        value: Value,
    ) -> Result<Uuid, DurableJobStoreError> {
        let job: WireJob = serde_json::from_value(value).map_err(|_| rejected())?;
        if job.id != prepared.id.to_string() || job.payload != prepared.payload {
            return Err(rejected());
        }
        Ok(prepared.id)
    }

    pub async fn claim(
        &self,
        owner: &str,
        lease: Duration,
    ) -> Result<Option<HostedClaim>, DurableJobStoreError> {
        self.claim_lane(owner, lease, None).await
    }

    /// `lane` [`SMALL_LANE`]: the coordinator selects only small-job-lane jobs
    /// (NAN-4290, `contract.mjs` `smallJob`); `None`: any queued job, FIFO.
    pub async fn claim_lane(
        &self,
        owner: &str,
        lease: Duration,
        lane: Option<&str>,
    ) -> Result<Option<HostedClaim>, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Runner || !valid_id(owner) {
            return Err(rejected());
        }
        let lease_ms = lease_millis(lease)?;
        let mut command = json!({"op":"claim","owner":owner,"lease_ms":lease_ms});
        if let Some(lane) = lane {
            if lane != SMALL_LANE {
                return Err(rejected());
            }
            command["lane"] = json!(lane);
        }
        let value = self.execute(command).await?;
        if value.is_null() {
            return Ok(None);
        }
        self.decode_claim(value, owner).map(Some)
    }

    /// Recover at most 100 expired leases using the attested namespace policy.
    /// Callers must not substitute a per-request retry budget.
    pub async fn reconcile(&self) -> Result<usize, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Runner {
            return Err(rejected());
        }
        let count = self.execute(json!({"op":"reconcile"})).await?;
        count
            .as_u64()
            .filter(|n| *n <= 100)
            .map(|n| n as usize)
            .ok_or_else(rejected)
    }

    /// Polling authenticates the immutable submission in queued and terminal
    /// states too. Outages and invalid records never become a false 404.
    /// Returns metadata, not permission to read result bytes. Result consumers
    /// must apply the current moving retention window and caller source scope.
    pub async fn get(&self, id: Uuid) -> Result<Option<SearchJob>, DurableJobStoreError> {
        Ok(self.get_with_progress(id).await?.map(|(job, _)| job))
    }

    pub(crate) async fn get_with_progress(
        &self,
        id: Uuid,
    ) -> Result<Option<(SearchJob, Option<SearchJobProgress>)>, DurableJobStoreError> {
        self.key(id)?;
        let value = self.execute(json!({"op":"get","job_id":id})).await?;
        if value.is_null() {
            return Ok(None);
        }
        // Decode/authenticate the complete record before exposing advisory data.
        let percent = value.get("progress").and_then(Value::as_u64);
        let phase = value
            .get("phase")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let attempt = value
            .get("attempt")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let job = self.decode_job(value, id)?;
        let progress = percent.map(|n| SearchJobProgress {
            percent: n as u8,
            phase,
            attempt,
            rows_scanned: 0,
            rows_total: 0,
            elapsed_ms: job.elapsed_ms(),
        });
        Ok(Some((job, progress)))
    }

    /// Internal listing only. Every returned job is authenticated before caller
    /// user/source-scope filtering; this is not a public authorization boundary.
    pub async fn list_page(
        &self,
        limit: u8,
        after: Option<&HostedJobCursor>,
    ) -> Result<HostedJobPage, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Producer || !(1..=25).contains(&limit) {
            return Err(rejected());
        }
        if let Some(cursor) = after {
            let id = Uuid::parse_str(&cursor.position.id).map_err(|_| rejected())?;
            if cursor.binding != self.key(id)? {
                return Err(rejected());
            }
        }
        let value = self
            .execute(json!({"op":"list_page","limit":limit,"after":after.map(|c|&c.position)}))
            .await?;
        self.decode_page(value, limit, after)
    }

    fn decode_page(
        &self,
        value: Value,
        limit: u8,
        after: Option<&HostedJobCursor>,
    ) -> Result<HostedJobPage, DurableJobStoreError> {
        let page: WirePage = serde_json::from_value(value).map_err(|_| rejected())?;
        if page.jobs.len() > usize::from(limit) || (page.jobs.is_empty() && page.next.is_some()) {
            return Err(rejected());
        }
        let mut prior = after.map(|c| c.position.clone());
        let mut jobs = Vec::with_capacity(page.jobs.len());
        for value in page.jobs {
            let position = PagePosition {
                created: value["created"].as_i64().ok_or_else(rejected)?,
                id: value["id"].as_str().ok_or_else(rejected)?.to_string(),
            };
            if prior.as_ref().is_some_and(|p| {
                position.created > p.created
                    || (position.created == p.created && position.id >= p.id)
            }) {
                return Err(rejected());
            }
            let id = Uuid::parse_str(&position.id).map_err(|_| rejected())?;
            jobs.push(self.decode_job(value, id)?);
            prior = Some(position);
        }
        let next = page
            .next
            .map(|position| {
                if prior.as_ref() != Some(&position) {
                    return Err(rejected());
                }
                let binding = self.key(Uuid::parse_str(&position.id).map_err(|_| rejected())?)?;
                Ok(HostedJobCursor { position, binding })
            })
            .transpose()?;
        Ok(HostedJobPage { jobs, next })
    }

    fn decode_job(&self, value: Value, id: Uuid) -> Result<SearchJob, DurableJobStoreError> {
        let job: WireJob = serde_json::from_value(value).map_err(|_| rejected())?;
        if job.id != id.to_string()
            || job.payload.len() > 65_536
            || job.fence > MAX_SAFE_INTEGER
            || job.created <= 0
            || job.created as u64 > MAX_SAFE_INTEGER
            || job.progress.is_some_and(|n| n > 100)
            || job
                .phase
                .as_deref()
                .is_some_and(|phase| !valid_phase(phase))
            || job.error.as_ref().is_some_and(|s| s.len() > 1024)
            || job.owner.as_ref().is_some_and(|s| !valid_id(s))
        {
            return Err(rejected());
        }
        let status: SearchJobStatus =
            serde_json::from_value(json!(job.status)).map_err(|_| rejected())?;
        let terminal = matches!(
            status,
            SearchJobStatus::Completed | SearchJobStatus::Failed | SearchJobStatus::Cancelled
        );
        if terminal != job.completed.is_some()
            || (status == SearchJobStatus::Completed) != job.result.is_some()
            || (matches!(
                status,
                SearchJobStatus::Running | SearchJobStatus::Completed
            )) != job.owner.is_some()
            || (status == SearchJobStatus::Running) != job.expires.is_some()
            || job
                .expires
                .is_some_and(|ms| ms <= 0 || ms as u64 > MAX_SAFE_INTEGER)
            || job
                .completed
                .is_some_and(|ms| ms <= 0 || ms as u64 > MAX_SAFE_INTEGER)
            || (matches!(
                status,
                SearchJobStatus::Running | SearchJobStatus::Completed
            ) && (job.attempt == 0 || job.fence == 0))
        {
            return Err(rejected());
        }
        let key = self.key(id)?;
        let envelope: DurableJobEnvelope =
            serde_json::from_str(&job.payload).map_err(|_| rejected())?;
        let decoded = decode_hosted_job(&envelope, self.context(id, &key))?;
        let result_ref = job
            .result
            .as_deref()
            .map(|raw| {
                if raw.len() > 65_536 {
                    return Err(rejected());
                }
                let result: SearchJobResultRef =
                    serde_json::from_str(raw).map_err(|_| rejected())?;
                self.validate_result_metadata(id, job.attempt, job.fence, &result)?;
                Ok(result)
            })
            .transpose()?;
        Ok(SearchJob {
            id: id.to_string(),
            tenant_id: self.tenant.tenant_id(),
            status,
            query_id: String::new(),
            user_id: Some(decoded.user_id),
            priority: decoded.priority,
            queue_position: None,
            created_at: chrono::DateTime::from_timestamp_millis(decoded.created_at_ms)
                .ok_or_else(rejected)?,
            completed_at: job
                .completed
                .map(|ms| chrono::DateTime::from_timestamp_millis(ms).ok_or_else(rejected))
                .transpose()?,
            request: decoded.request,
            result: None,
            error: job.error,
            backend: SearchJobBackend::LakeDurable,
            attempt: job.attempt,
            fence: job.fence,
            result_ref,
            generation_pin: Some(decoded.generation_pin),
            task: Some(decoded.task),
            durable_authority: Some(decoded.authority),
            scope_deny: Some(decoded.scope_deny),
        })
    }

    fn decode_claim(&self, value: Value, owner: &str) -> Result<HostedClaim, DurableJobStoreError> {
        let job: WireJob = serde_json::from_value(value).map_err(|_| rejected())?;
        let id = Uuid::parse_str(&job.id).map_err(|_| rejected())?;
        if job.id != id.to_string()
            || job.status != "running"
            || job.owner.as_deref() != Some(owner)
            || job.created <= 0
            || job.created as u64 > MAX_SAFE_INTEGER
            || job.attempt == 0
            || job.fence == 0
            || job.fence > MAX_SAFE_INTEGER
            || job.result.is_some()
            || job.completed.is_some()
            || job.progress.is_some_and(|n| n > 100)
            || job
                .phase
                .as_deref()
                .is_some_and(|phase| !valid_phase(phase))
            || job.error.as_ref().is_some_and(|s| s.len() > 1024)
            || job.execution_failures >= self.policy.max_execution_failures
            || job.lease_recoveries >= self.policy.max_lease_recoveries
            || job.payload.len() > 65_536
        {
            return Err(rejected());
        }
        let expires = job.expires.ok_or_else(rejected)?;
        if expires <= Utc::now().timestamp_millis() || expires as u64 > MAX_SAFE_INTEGER {
            return Err(rejected());
        }
        let envelope: DurableJobEnvelope =
            serde_json::from_str(&job.payload).map_err(|_| rejected())?;
        let key = self.key(id)?;
        let claim = decode_hosted_claim(
            &envelope,
            self.context(id, &key),
            HostedClaimLease {
                owner: owner.into(),
                attempt: job.attempt,
                fence: job.fence,
                expires_at_ms: expires,
                resource_class: job
                    .resource_class
                    .unwrap_or(DurableQueryResourceClass::Medium),
            },
        )?;
        Ok(HostedClaim { claim, key })
    }

    pub async fn renew(
        &self,
        claim: &HostedClaim,
        lease: Duration,
    ) -> Result<bool, DurableJobStoreError> {
        let mut command = self.stamp(claim, "renew")?;
        command["lease_ms"] = json!(lease_millis(lease)?);
        self.boolean(command).await
    }

    pub async fn progress(
        &self,
        claim: &HostedClaim,
        percent: u32,
    ) -> Result<bool, DurableJobStoreError> {
        if percent > 100 {
            return Err(rejected());
        }
        let mut command = self.stamp(claim, "progress")?;
        command["progress"] = json!(percent);
        self.boolean(command).await
    }

    pub async fn fail(
        &self,
        claim: &HostedClaim,
        retryable: bool,
        promote: bool,
        error: &str,
    ) -> Result<bool, DurableJobStoreError> {
        if error.trim().is_empty() || error.len() > 256 || error.chars().any(char::is_control) {
            return Err(rejected());
        }
        let mut command = self.stamp(claim, "fail")?;
        command["retryable"] = json!(retryable);
        command["promote_resource_class"] = json!(promote);
        command["error"] = json!(error);
        self.boolean(command).await
    }

    pub async fn complete(
        &self,
        claim: &HostedClaim,
        result: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError> {
        self.boolean(self.result_command(claim, result)?).await
    }

    fn result_command(
        &self,
        claim: &HostedClaim,
        result: &SearchJobResultRef,
    ) -> Result<Value, DurableJobStoreError> {
        let mut command = self.stamp(claim, "complete")?;
        self.validate_result(
            Uuid::parse_str(&claim.claim.job_id).map_err(|_| rejected())?,
            claim.claim.attempt,
            claim.claim.fence,
            result,
        )?;
        if matches!(&self.backend, CoordinatorBackend::Postgres(_)) {
            result
                .verify_retention_for_range(
                    self.tenant,
                    &claim.claim.request.time_range,
                    Utc::now(),
                )
                .map_err(|_| rejected())?;
        }
        command["result"] = json!(serde_json::to_string(result).map_err(|_| rejected())?);
        Ok(command)
    }

    fn validate_result(
        &self,
        id: Uuid,
        attempt: u32,
        fence: u64,
        result: &SearchJobResultRef,
    ) -> Result<(), DurableJobStoreError> {
        result
            .verify_retention_at(self.tenant, Utc::now())
            .map_err(|_| rejected())?;
        self.validate_result_metadata(id, attempt, fence, result)
    }

    fn validate_result_metadata(
        &self,
        id: Uuid,
        attempt: u32,
        fence: u64,
        result: &SearchJobResultRef,
    ) -> Result<(), DurableJobStoreError> {
        result.verify_tenant(self.tenant).map_err(|_| rejected())?;
        let tenant = self.signer.tenant_id().to_string();
        let tenant_hash = hex::encode(Sha256::digest(tenant.as_bytes()));
        let prefix = match &self.backend {
            CoordinatorBackend::Hosted(_) => format!("s3://nano-shared-r2-{tenant}/{tenant}"),
            CoordinatorBackend::Postgres(coordinator) => coordinator.result_prefix(),
        };
        let expected = format!(
            "{prefix}/durable-query-result/v1/tenant-{tenant_hash}/job-{id}/attempt-attempt-{attempt}-fence-{fence}/manifest.json"
        );
        if result.manifest_uri != expected
            || result.manifest_sha256.len() != 64
            || !result
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || result.parts > 100_000
            || result.page_rows == 0
            || result.page_rows > 50_000
        {
            return Err(rejected());
        }
        Ok(())
    }

    pub async fn cancel(&self, id: Uuid) -> Result<bool, DurableJobStoreError> {
        if self.role != HostedCoordinatorRole::Producer {
            return Err(rejected());
        }
        self.key(id)?;
        self.boolean(json!({"op":"cancel","job_id":id})).await
    }

    pub async fn cancel_claim(&self, claim: &HostedClaim) -> Result<bool, DurableJobStoreError> {
        self.boolean(self.stamp(claim, "cancel_claim")?).await
    }

    /// NAN-2653: fenced no-cost hand-back of the current attempt. A Worker
    /// deployed before `release_claim` answers 403 (runner op allowlist) or
    /// 409 (contract rejection); both map to `Unsupported` so the runner falls
    /// back to today's retryable `fail` rather than a store-outage backoff.
    pub async fn release_claim(&self, claim: &HostedClaim) -> Result<bool, DurableJobStoreError> {
        let mut command = self.stamp(claim, "release_claim")?;
        command["epoch"] = json!(self.epoch);
        let CoordinatorBackend::Hosted(transport) = &self.backend else {
            return self.boolean(command).await;
        };
        match transport.execute_detailed(&command).await {
            Ok(value) => value.as_bool().ok_or_else(rejected),
            Err(failure)
                if matches!(
                    failure.kind,
                    CoordinatorTransportError::AccessDenied | CoordinatorTransportError::Rejected
                ) =>
            {
                Err(DurableJobStoreError::Unsupported)
            }
            Err(failure) => Err(unavailable(failure)),
        }
    }

    fn context<'a>(&'a self, id: Uuid, key: &'a str) -> HostedClaimContext<'a> {
        HostedClaimContext {
            tenant: self.tenant,
            assignment_revision: self.assignment.entitlement_revision,
            signer: &self.signer,
            job_key: key,
            job_id: id,
        }
    }
    fn stamp(&self, claim: &HostedClaim, op: &str) -> Result<Value, DurableJobStoreError> {
        let job = &claim.claim;
        let id = Uuid::parse_str(&job.job_id).map_err(|_| rejected())?;
        if self.role != HostedCoordinatorRole::Runner || self.key(id)? != claim.key {
            return Err(rejected());
        }
        Ok(
            json!({"op":op,"job_id":job.job_id,"owner":job.lease_owner,"attempt":job.attempt,"fence":job.fence}),
        )
    }
    async fn execute(&self, mut command: Value) -> Result<Value, DurableJobStoreError> {
        command["epoch"] = json!(self.epoch);
        match &self.backend {
            CoordinatorBackend::Hosted(transport) => transport
                .execute_detailed(&command)
                .await
                .map_err(unavailable),
            CoordinatorBackend::Postgres(coordinator) => coordinator.execute(&command).await,
        }
    }
    async fn boolean(&self, command: Value) -> Result<bool, DurableJobStoreError> {
        self.execute(command).await?.as_bool().ok_or_else(rejected)
    }
}
/// Keep the store-outage classification callers rely on, but carry the
/// operation, HTTP status and closed coordinator error code (never bodies,
/// tokens or endpoints) so a refusal is diagnosable from the runner log.
/// The transport has already logged the failure at warn.
fn unavailable(failure: CoordinatorFailure) -> DurableJobStoreError {
    DurableJobStoreError::Unavailable(failure.to_string())
}
fn lease_millis(lease: Duration) -> Result<u64, DurableJobStoreError> {
    if lease < Duration::from_secs(5) || lease > Duration::from_secs(3600) {
        return Err(rejected());
    }
    u64::try_from(lease.as_millis()).map_err(|_| rejected())
}

#[cfg(all(test, feature = "enterprise"))]
#[path = "job_coordinator_client_tests.rs"]
mod tests;
