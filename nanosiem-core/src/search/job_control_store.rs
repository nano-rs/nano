// SPDX-License-Identifier: AGPL-3.0-or-later
//! Producer/read interface, separate from runner leases and legacy inline writes.
use super::{
    job_coordinator_client::{HostedCoordinatorClient, HostedJobCursor},
    job_envelope::HostedJobSubmission,
    jobs::*,
    QueryPriority, SearchRequest,
};
use crate::auth::ScopeSet;
use async_trait::async_trait;
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

#[async_trait]
pub trait DurableJobControlStore: Send + Sync + std::fmt::Debug {
    fn matches_binding(
        &self,
        tenant: super::SearchTenantScope,
        assignment: super::job_coordinator_client::HostedAssignment,
    ) -> bool;
    async fn create_durable_queued(
        &self,
        request: SearchRequest,
        task: &DurableLakeTask,
        user: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError>;
    /// Idempotent promotion uses the original ID and signed creation timestamp.
    async fn submit_interactive_fallback(
        &self,
        _job: &SearchJob,
        _scope: &ScopeSet,
    ) -> Result<(), DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }
    async fn get_checked(&self, id: &str) -> Result<Option<SearchJob>, DurableJobStoreError>;
    async fn get_status_checked(
        &self,
        id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError>;
    async fn get_snapshot_checked(&self, id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        let Some(job) = self.get_checked(id).await? else { return Ok(None); };
        Ok(self.get_status_checked(id).await?.map(|status| (job, status)))
    }
    async fn cancel_checked(&self, id: &str) -> Result<bool, DurableJobStoreError>;
    async fn list_for_user_checked(
        &self,
        user: Uuid,
    ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError>;
    async fn list_all_checked(
        &self,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError>;
}

/// Hosted UUIDv7 jobs only consult the coordinator. UUIDv8 identifies the
/// explicit Redis interactive lane, never an in-memory fallback. A queued Redis
/// record is a promotion barrier; the coordinator owns execution from then on.
/// After Redis expiry, the same UUID resolves a durable fallback without an
/// index. Missing inline jobs stay missing. Redis outages fail closed.
pub struct JobControlView<'a> {
    pub(super) legacy: &'a dyn SearchJobStore,
    pub(super) hosted: Option<&'a dyn DurableJobControlStore>,
}
impl<'a> JobControlView<'a> {
    /// A view over one legacy/Dragonfly store with no hosted coordinator —
    /// the shape every enterprise-shared Redis tenant view takes today. Lets
    /// route-level code (and its tests) exercise the exact list/get contract
    /// against a tenant-pinned store without constructing a `SearchService`.
    pub fn legacy(store: &'a dyn SearchJobStore) -> Self {
        Self {
            legacy: store,
            hosted: None,
        }
    }
    pub async fn create_durable_queued(
        &self,
        request: SearchRequest,
        task: &DurableLakeTask,
        user: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
    crate::request_timing::timed(crate::request_timing::Phase::Ledger, async {

        let reuse_key = super::recent_reuse_jobs::key(&request, &request.query, user, scope, authority);
        let window = (request.time_range.start, request.time_range.end);
        let plain_search = matches!(task, DurableLakeTask::SearchNplV1 | DurableLakeTask::SearchNplShedV1 { .. });
        let created = match self.hosted {
            Some(s) => {
                s.create_durable_queued(request, task, user, priority, scope, generation, authority)
                    .await
            }
            None => {
                self.legacy
                    .create_durable_queued(
                        request, task, user, priority, scope, generation, authority,
                    )
                    .await
            }
        };
        if let (Ok(id), true) = (&created, plain_search) {
            super::in_flight_jobs::InFlightJobs::global().record(id, user, window.0, window.1);
            if let Some(key) = reuse_key {
                super::recent_reuse_jobs::RecentReuseJobs::global().record(key, id);
            }
        }
        created

    }).await
}
    pub async fn create_interactive_lake(
        &self,
        request: SearchRequest,
        user: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        let reuse_key = super::recent_reuse_jobs::key(&request, &request.query, user, scope, authority);
        let window = (request.time_range.start, request.time_range.end);
        let created = self.legacy
            .create_interactive_lake(request, user, priority, scope, generation, authority)
            .await;
        if let Ok(id) = &created {
            super::in_flight_jobs::InFlightJobs::global().record(id, user, window.0, window.1);
            if let Some(key) = reuse_key {
                super::recent_reuse_jobs::RecentReuseJobs::global().record(key, id);
            }
        }
        created
    }

    pub fn supports_interactive_lake(&self) -> bool {
        self.legacy.supports_interactive_lake()
    }

    pub fn uses_interactive_lane(&self, id: &str) -> bool {
        self.hosted.is_some() && is_interactive_job_id(id)
    }

    pub async fn promote_interactive_lake(
        &self,
        id: &str,
        scope: &ScopeSet,
    ) -> Result<(), DurableJobStoreError> {
        let Some(hosted) = self.hosted else {
            return self.legacy.promote_interactive_lake(id, scope).await;
        };
        if !self.uses_interactive_lane(id) || !self.supports_interactive_lake() {
            return Err(DurableJobStoreError::Unsupported);
        }
        let Some(job) = self.legacy.get_checked(id).await? else {
            return Ok(());
        };
        if job.scope_deny.as_ref() != Some(scope.deny_set()) {
            return Err(DurableJobStoreError::ClaimRejected);
        }
        if job.status == SearchJobStatus::Cancelled {
            hosted.cancel_checked(id).await?;
            return Ok(());
        }
        if !self.legacy.begin_hosted_promotion(id).await? {
            return Ok(());
        }
        let submission = hosted.submit_interactive_fallback(&job, scope).await;
        // Cancellation can race the network submission. Never let it revive
        // the inline job, and cancel a newly admitted durable attempt as well.
        if !self
            .legacy
            .get_checked(id)
            .await?
            .is_some_and(|job| job.status == SearchJobStatus::Queued)
        {
            hosted.cancel_checked(id).await?;
        }
        submission
    }

    pub async fn get_snapshot_checked(&self, id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        crate::request_timing::timed(crate::request_timing::Phase::Ledger, async {
            let Some(hosted) = self.hosted else { return self.legacy.get_snapshot_checked(id).await; };
            if self.uses_interactive_lane(id) && self.supports_interactive_lake() {
                let snapshot = self.legacy.get_snapshot_checked(id).await?;
                if snapshot.as_ref().is_some_and(|(job, _)| job.status != SearchJobStatus::Queued) { return Ok(snapshot); }
                return Ok(hosted.get_snapshot_checked(id).await?.or(snapshot));
            }
            hosted.get_snapshot_checked(id).await
        }).await
    }

    pub async fn get_checked(&self, id: &str) -> Result<Option<SearchJob>, DurableJobStoreError> {
    crate::request_timing::timed(crate::request_timing::Phase::Ledger, async {

        let Some(hosted) = self.hosted else {
            return self.legacy.get_checked(id).await;
        };
        if self.uses_interactive_lane(id) && self.supports_interactive_lake() {
            let job = self.legacy.get_checked(id).await?;
            if job
                .as_ref()
                .is_some_and(|job| job.status != SearchJobStatus::Queued)
            {
                return Ok(job);
            }
            return Ok(hosted.get_checked(id).await?.or(job));
        }
        hosted.get_checked(id).await

    }).await
}

    pub async fn get_status_checked(
        &self,
        id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
    crate::request_timing::timed(crate::request_timing::Phase::Ledger, async {

        let Some(hosted) = self.hosted else {
            return self.legacy.get_status_checked(id).await;
        };
        if self.uses_interactive_lane(id) && self.supports_interactive_lake() {
            let job = self.legacy.get_checked(id).await?;
            if job
                .as_ref()
                .is_some_and(|job| job.status != SearchJobStatus::Queued)
            {
                return self.legacy.get_status_checked(id).await;
            }
            if let Some(status) = hosted.get_status_checked(id).await? {
                return Ok(Some(status));
            }
            return if job.is_some() {
                self.legacy.get_status_checked(id).await
            } else {
                Ok(None)
            };
        }
        hosted.get_status_checked(id).await

    }).await
}

    pub async fn cancel_checked(&self, id: &str) -> Result<bool, DurableJobStoreError> {
        let Some(hosted) = self.hosted else {
            return Ok(self.legacy.cancel_interactive_checked(id).await?
                == InteractiveJobCancellation::Cancelled);
        };
        if self.uses_interactive_lane(id) && self.supports_interactive_lake() {
            // Authenticate the record before mutation. The Lua transition,
            // rather than this read, decides who won promotion vs cancellation.
            if self.legacy.get_checked(id).await?.is_some() {
                return match self.legacy.cancel_interactive_checked(id).await? {
                    InteractiveJobCancellation::Cancelled => Ok(true),
                    InteractiveJobCancellation::Inactive => Ok(false),
                    InteractiveJobCancellation::Hosted => hosted.cancel_checked(id).await,
                };
            }
        }
        hosted.cancel_checked(id).await
    }
    pub async fn list_for_user_checked(
        &self,
        user: Uuid,
    ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
        match self.hosted {
            Some(s) => {
                let mut jobs = s.list_for_user_checked(user).await?;
                if self.supports_interactive_lake() {
                    for job in self.legacy.list_for_user_checked(user).await? {
                        if !is_interactive_job_id(&job.job_id) {
                            continue;
                        }
                        if job.status == SearchJobStatus::Queued
                            && jobs.iter().any(|j| j.job_id == job.job_id)
                        {
                            continue;
                        }
                        jobs.retain(|j| j.job_id != job.job_id);
                        jobs.push(job);
                    }
                }
                jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at_ms));
                Ok(jobs)
            }
            None => self.legacy.list_for_user_checked(user).await,
        }
    }
    pub async fn list_all_checked(
        &self,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError> {
        match self.hosted {
            Some(s) => {
                let mut jobs = s.list_all_checked(deny).await?;
                if self.supports_interactive_lake() {
                    for job in self.legacy.list_all_checked(deny).await? {
                        if !is_interactive_job_id(&job.job_id) {
                            continue;
                        }
                        if job.status == SearchJobStatus::Queued
                            && jobs.iter().any(|j| j.job_id == job.job_id)
                        {
                            continue;
                        }
                        jobs.retain(|j| j.job_id != job.job_id);
                        jobs.push(job);
                    }
                }
                jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at_ms));
                Ok(jobs)
            }
            None => self.legacy.list_all_checked(deny).await,
        }
    }
}

fn parsed_id(id: &str) -> Result<Uuid, DurableJobStoreError> {
    let uuid = Uuid::parse_str(id).map_err(|_| DurableJobStoreError::ClaimRejected)?;
    if uuid.is_nil() || uuid.to_string() != id {
        return Err(DurableJobStoreError::ClaimRejected);
    }
    Ok(uuid)
}

#[async_trait]
impl DurableJobControlStore for HostedCoordinatorClient {
    fn matches_binding(
        &self,
        tenant: super::SearchTenantScope,
        assignment: super::job_coordinator_client::HostedAssignment,
    ) -> bool {
        self.matches_producer_binding(tenant, assignment)
    }
    async fn create_durable_queued(
        &self,
        request: SearchRequest,
        task: &DurableLakeTask,
        user: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        let authority = authority.ok_or(DurableJobStoreError::ClaimRejected)?;
        let prepared = self.prepare(
            Uuid::now_v7(),
            HostedJobSubmission {
                request: &request,
                task,
                user_id: user,
                priority,
                scope,
                generation_pin: generation,
                authority,
                created_at_ms: chrono::Utc::now().timestamp_millis(),
            },
        )?;
        submit_prepared(self, &prepared)
            .await
            .map(|id| id.to_string())
    }
    async fn submit_interactive_fallback(
        &self,
        job: &SearchJob,
        scope: &ScopeSet,
    ) -> Result<(), DurableJobStoreError> {
        let prepared = self.prepare(
            parsed_id(&job.id)?,
            HostedJobSubmission {
                request: &job.request,
                task: &DurableLakeTask::SearchNplV1,
                user_id: job.user_id.ok_or(DurableJobStoreError::ClaimRejected)?,
                priority: job.priority,
                scope,
                generation_pin: job
                    .generation_pin
                    .as_ref()
                    .ok_or(DurableJobStoreError::ClaimRejected)?,
                authority: job
                    .durable_authority
                    .as_ref()
                    .ok_or(DurableJobStoreError::ClaimRejected)?,
                created_at_ms: job.created_at.timestamp_millis(),
            },
        )?;
        submit_prepared(self, &prepared).await.map(|_| ())
    }
    async fn get_checked(&self, id: &str) -> Result<Option<SearchJob>, DurableJobStoreError> {
        self.get(parsed_id(id)?).await
    }
    async fn get_status_checked(
        &self,
        id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
        Ok(DurableJobControlStore::get_snapshot_checked(self, id).await?.map(|(_, status)| status))
    }
    async fn get_snapshot_checked(&self, id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        let Some((job, progress)) = self.get_with_progress(parsed_id(id)?).await? else {
            return Ok(None);
        };
        if let Some(reference) = &job.result_ref {
            reference.verify_retention_for_range(
                self.tenant_scope(),
                &job.request.time_range,
                chrono::Utc::now(),
            )?;
        }
        // Object references remain server-side. The HTTP layer checks current
        // authority/scope/retention again before exposing or fetching results.
        // Rows are unavailable; phase and attempt remain advisory and fenced.
        let progress = progress.filter(|_| job.status == SearchJobStatus::Running);
        let status = SearchJobStatusResponse {
            job_id: job.id.clone(),
            status: job.status.clone(),
            progress,
            result: None,
            result_ref: job.result_ref.clone(),
            durable_result: None,
            error: job.error.clone(),
            error_code: super::jobs::search_job_error_code(job.error.as_deref()),
            queue_position: None,
            estimated_wait_seconds: None,
            task_kind: job.task.as_ref().map(|t| t.kind().to_string()),
            query: Some(job.request.query.clone()),
            time_range: Some(job.request.time_range.clone()),
            dataset: job.request.dataset.clone(),
        };
        Ok(Some((job, status)))
    }
    async fn cancel_checked(&self, id: &str) -> Result<bool, DurableJobStoreError> {
        self.cancel(parsed_id(id)?).await
    }
    async fn list_for_user_checked(
        &self,
        user: Uuid,
    ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
        collect_summaries(self, |job| user_summary(job, user)).await
    }
    async fn list_all_checked(
        &self,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError> {
        collect_summaries(self, |job| admin_summary(job, deny)).await
    }
}
async fn submit_prepared(
    client: &HostedCoordinatorClient,
    prepared: &super::job_coordinator_client::PreparedHostedJob,
) -> Result<Uuid, DurableJobStoreError> {
    // Retry exactly the same signed bytes after an ambiguous acknowledgement.
    // Never regenerate the identifier or timestamp within this admission.
    for attempt in 0..2 {
        match client.submit(prepared).await {
            Ok(id) => return Ok(id),
            Err(DurableJobStoreError::Unavailable(_)) if attempt == 0 => continue,
            Err(DurableJobStoreError::Unavailable(_)) => {
                // Both acknowledgements may be lost even though the runner
                // already owns/completed this exact job. One bounded read
                // recovers its receipt without issuing another submission.
                return client.recover_submission(prepared).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded submission loop returns on its final attempt")
}
fn user_summary(job: &SearchJob, user: Uuid) -> Option<SearchJobSummary> {
    (job.user_id == Some(user)).then(|| SearchJobSummary {
        job_id: job.id.clone(),
        status: job.status.clone(),
        query: truncate_query_preview(&job.request.query),
        created_at_ms: job.created_at_ms(),
        elapsed_ms: job.elapsed_ms(),
        queue_position: None,
        priority: job.priority,
        task_kind: job.task.as_ref().map(|t| t.kind().to_string()),
    })
}
fn admin_summary(job: &SearchJob, deny: &BTreeSet<String>) -> Option<AdminSearchJobSummary> {
    job.result_visible_under(deny)
        .then(|| AdminSearchJobSummary {
            job_id: job.id.clone(),
            status: job.status.clone(),
            user_id: job.user_id.map(|u| u.to_string()),
            query: truncate_query_preview(&job.request.query),
            created_at_ms: job.created_at_ms(),
            elapsed_ms: job.elapsed_ms(),
            queue_position: None,
            priority: job.priority,
            task_kind: job.task.as_ref().map(|t| t.kind().to_string()),
        })
}

async fn collect_summaries<T, F>(
    client: &HostedCoordinatorClient,
    filter: F,
) -> Result<Vec<T>, DurableJobStoreError>
where
    F: Fn(&SearchJob) -> Option<T>,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut snapshot = client.history.lock().await;
        if let Some((at, jobs)) = snapshot.as_ref() {
            if at.elapsed() < Duration::from_secs(2) {
                return Ok(jobs.iter().filter_map(&filter).collect());
            }
        }
        // History is served entirely over the coordinator HTTP transport; it
        // never acquires the search-path PostgreSQL pool. Coalesce concurrent
        // polls and cap cold reads at ten pages of the most recent tenant jobs.
        let mut cursor: Option<HostedJobCursor> = None;
        let mut jobs = Vec::new();
        for _ in 0..10 {
            let page = client.list_page(25, cursor.as_ref()).await?;
            jobs.extend(page.jobs);
            cursor = page.next;
            if cursor.is_none() { break; }
        }
        let summaries = jobs.iter().filter_map(&filter).collect();
        *snapshot = Some((std::time::Instant::now(), jobs));
        Ok(summaries)
    })
    .await
    .map_err(|_| DurableJobStoreError::Unavailable("hosted job history timed out".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Unavailable;
    fn outage<T>() -> Result<T, DurableJobStoreError> {
        Err(DurableJobStoreError::Unavailable("synthetic outage".into()))
    }
    #[async_trait]
    impl DurableJobControlStore for Unavailable {
        fn matches_binding(
            &self,
            _: super::super::SearchTenantScope,
            _: super::super::job_coordinator_client::HostedAssignment,
        ) -> bool {
            true
        }
        async fn create_durable_queued(
            &self,
            _: SearchRequest,
            _: &DurableLakeTask,
            _: Uuid,
            _: QueryPriority,
            _: &ScopeSet,
            _: &DurableLakeGenerationPin,
            _: Option<&DurableSearchJobAuthority>,
        ) -> Result<String, DurableJobStoreError> {
            outage()
        }
        async fn get_checked(&self, _: &str) -> Result<Option<SearchJob>, DurableJobStoreError> {
            outage()
        }
        async fn get_status_checked(
            &self,
            _: &str,
        ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
            outage()
        }
        async fn cancel_checked(&self, _: &str) -> Result<bool, DurableJobStoreError> {
            outage()
        }
        async fn list_for_user_checked(
            &self,
            _: Uuid,
        ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
            outage()
        }
        async fn list_all_checked(
            &self,
            _: &BTreeSet<String>,
        ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError> {
            outage()
        }
    }
    fn request() -> SearchRequest {
        serde_json::from_value(serde_json::json!({"query":"界".repeat(50),"time_range":{
            "start":chrono::Utc::now()-chrono::Duration::hours(1),"end":chrono::Utc::now()}}))
        .unwrap()
    }
    #[tokio::test]
    async fn explicit_hosted_outage_never_reads_a_legacy_job_or_returns_fake_empty_lists() {
        let legacy = InMemoryJobStore::new();
        let id = legacy
            .create(request(), &ScopeSet::unrestricted())
            .await
            .unwrap();
        let normal = JobControlView {
            legacy: &legacy,
            hosted: None,
        };
        assert!(normal.get_checked(&id).await.unwrap().is_some());
        let hosted = JobControlView {
            legacy: &legacy,
            hosted: Some(&Unavailable),
        };
        assert!(hosted.get_checked(&id).await.is_err());
        assert!(hosted.get_status_checked(&id).await.is_err());
        assert!(hosted.list_for_user_checked(Uuid::now_v7()).await.is_err());
        assert!(hosted.list_all_checked(&BTreeSet::new()).await.is_err());
        assert!(normal.get_checked(&id).await.unwrap().is_some());
    }
    #[test]
    fn summaries_enforce_user_ownership_and_admin_source_scope_before_returning_previews() {
        let user = Uuid::now_v7();
        let scope = ScopeSet::from_denied(["restricted".to_string()].into_iter().collect());
        let job = SearchJob::new_queued(
            Uuid::now_v7().to_string(),
            request(),
            user,
            QueryPriority::Analytics,
            &scope,
        );
        assert!(user_summary(&job, Uuid::now_v7()).is_none());
        assert!(user_summary(&job, user).unwrap().query.len() <= 100);
        assert!(admin_summary(&job, &["new-denial".into()].into_iter().collect()).is_none());
        assert!(admin_summary(&job, scope.deny_set()).is_some());
    }
}

#[cfg(all(test, feature = "enterprise"))]
#[path = "job_control_store_tests.rs"]
mod lane_tests;
