// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async search job registry
//!
//! This module provides pluggable storage for async search jobs via the
//! `SearchJobStore` trait. Two implementations are available:
//! - `InMemoryJobStore` — DashMap-backed, single-instance (default for tests)
//! - `RedisJobStore` — Redis-backed, multi-instance (active/active deployments)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::auth::ScopeSet;

use super::admission::QueryPriority;
use super::types::{SearchRequest, SearchResponse};

/// Maximum number of concurrent jobs
const MAX_JOBS: usize = 1000;

/// Truncate a stored query for a job-list preview WITHOUT panicking on a
/// non-char-boundary byte offset.
///
/// NAN-2010 (F12/F15/F16/F17/F25): the client query is stored verbatim (before
/// any parse), and the previews sliced it with `&query[..97]` guarded only by a
/// byte-length check. A multibyte UTF-8 character straddling byte 97 made the
/// slice panic — and because `list_all` enumerates every user's jobs, an
/// unprivileged user's crafted query persistently broke `/api/search/admin/jobs`
/// for admins (cross-user DoS). Cut at the largest char boundary at or below 97.
fn truncate_query_preview(query: &str) -> String {
    if query.len() <= 100 {
        return query.to_string();
    }
    let mut end = 97;
    while end > 0 && !query.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &query[..end])
}

/// TTL for completed/failed jobs (5 minutes)
const COMPLETED_JOB_TTL: Duration = Duration::from_secs(300);

/// Status of an async search job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchJobStatus {
    /// Job is waiting in the admission queue
    Queued,
    /// Job is currently executing
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed with an error
    Failed,
    /// Job was cancelled by the user
    Cancelled,
}

impl std::fmt::Display for SearchJobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for SearchJobStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("unknown job status: {}", s)),
        }
    }
}

/// Progress information for a running search job
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobProgress {
    /// Number of rows scanned so far
    pub rows_scanned: u64,
    /// Estimated total rows to scan
    pub rows_total: u64,
    /// Completion percentage (0-100)
    pub percent: u8,
    /// Time elapsed since job started (milliseconds)
    pub elapsed_ms: u64,
}

/// An async search job
#[derive(Debug)]
pub struct SearchJob {
    /// Unique job identifier
    pub id: String,
    /// Current job status
    pub status: SearchJobStatus,
    /// ClickHouse query_id for progress tracking and cancellation
    pub query_id: String,
    /// Who owns this job
    pub user_id: Option<Uuid>,
    /// Queue priority level
    pub priority: QueryPriority,
    /// Queue position (1-based, set while queued)
    pub queue_position: Option<u32>,
    /// When the job was created (wall clock for cross-instance consistency)
    pub created_at: DateTime<Utc>,
    /// When the job completed (for TTL calculation)
    pub completed_at: Option<DateTime<Utc>>,
    /// The original search request
    pub request: SearchRequest,
    /// The search results (when completed)
    pub result: Option<SearchResponse>,
    /// Error message (when failed)
    pub error: Option<String>,
    /// NAN-2096: the effective source-scope deny-set the job EXECUTED under,
    /// stamped atomically at creation and immutable thereafter.
    ///
    /// `None` means the provenance is UNKNOWN — the job predates the stamp (a
    /// rolling upgrade left it in a shared Redis store) or its stored payload
    /// failed to decode. Unknown is never treated as `Some(empty)`; see
    /// [`SearchJob::result_visible_under`] for the (deliberately narrow) rule
    /// that governs it.
    pub scope_deny: Option<BTreeSet<String>>,
}

impl SearchJob {
    /// Create a new running job under `scope`.
    pub fn new(id: String, request: SearchRequest, scope: &ScopeSet) -> Self {
        Self {
            id,
            status: SearchJobStatus::Running,
            query_id: String::new(),
            user_id: None,
            priority: QueryPriority::Interactive,
            queue_position: None,
            created_at: Utc::now(),
            completed_at: None,
            request,
            result: None,
            error: None,
            scope_deny: Some(scope.deny_set().clone()),
        }
    }

    /// Create a new job in Queued state with user, priority and execution scope.
    pub fn new_queued(
        id: String,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Self {
        Self {
            id,
            status: SearchJobStatus::Queued,
            query_id: String::new(),
            user_id: Some(user_id),
            priority,
            queue_position: None,
            created_at: Utc::now(),
            completed_at: None,
            request,
            result: None,
            error: None,
            scope_deny: Some(scope.deny_set().clone()),
        }
    }

    /// NAN-2096: may a caller whose CURRENT effective source-scope deny-set is
    /// `current_deny` read this job's stored status/result?
    ///
    /// A completed result is a frozen snapshot of rows that were visible under
    /// the deny-set captured at submission. Ownership plus `search:execute` is
    /// not authorization to that snapshot after the caller's data scope
    /// narrows, so the read is re-decided here on every poll:
    ///
    /// * `current_deny ⊆ scope_deny` → every source that could have contributed
    ///   to the result is still visible to the caller. Allowed. (Widening the
    ///   caller's visibility is always safe — the result can only under-report.)
    /// * anything in `current_deny` that was NOT denied at submission → a source
    ///   the caller may no longer see could be in the result. Denied.
    /// * `scope_deny == None` (unknown provenance) → readable ONLY by a caller
    ///   whose deny-set is empty. That is not a fail-open exception: a caller
    ///   denied nothing may already read every source directly, so the snapshot
    ///   can hold nothing they are not entitled to. Every *restricted* caller is
    ///   refused, which is the fail-closed half that matters.
    ///
    /// This is deliberately set-based rather than row-level: results carry no
    /// per-row source manifest, so a mixed-source result fails closed as soon as
    /// ONE contributing source could be denied. Re-checking at READ time (rather
    /// than refusing to persist) is what makes revocation retroactive — an
    /// already-running job keeps executing under its submission scope, but its
    /// output stops being readable the moment the scope narrows.
    pub fn result_visible_under(&self, current_deny: &BTreeSet<String>) -> bool {
        match &self.scope_deny {
            Some(submitted) => current_deny.is_subset(submitted),
            None => current_deny.is_empty(),
        }
    }

    /// Check if this job has expired (completed/failed + TTL elapsed)
    pub fn is_expired(&self) -> bool {
        if self.status == SearchJobStatus::Running || self.status == SearchJobStatus::Queued {
            return false;
        }
        match self.completed_at {
            Some(completed) => {
                let elapsed = Utc::now().signed_duration_since(completed);
                elapsed
                    > chrono::Duration::from_std(COMPLETED_JOB_TTL)
                        .unwrap_or(chrono::Duration::seconds(300))
            }
            None => false,
        }
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        let elapsed = Utc::now().signed_duration_since(self.created_at);
        elapsed.num_milliseconds().max(0) as u64
    }

    /// Get created_at as milliseconds since Unix epoch
    pub fn created_at_ms(&self) -> u64 {
        self.created_at.timestamp_millis() as u64
    }
}

/// Response for job status API
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobStatusResponse {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// Progress information (when running)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<SearchJobProgress>,
    /// Search results (when completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SearchResponse>,
    /// Error message (when failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Queue position (1-based, when status is Queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Estimated wait time in seconds (when status is Queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_wait_seconds: Option<u32>,
}

/// Response for async search initiation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AsyncSearchResponse {
    /// Job ID for polling
    pub job_id: String,
    /// Initial status ("queued" or "running")
    pub status: String,
}

/// Summary of a search job for the active searches panel
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobSummary {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// Query text (truncated)
    pub query: String,
    /// Timestamp when job was created (ms since epoch)
    pub created_at_ms: u64,
    /// Time elapsed since creation (milliseconds)
    pub elapsed_ms: u64,
    /// Queue position (1-based, when queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Priority level
    pub priority: QueryPriority,
}

/// Summary of a search job for the admin search jobs page
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdminSearchJobSummary {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// User who created the job (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Query text (truncated)
    pub query: String,
    /// Timestamp when job was created (ms since epoch)
    pub created_at_ms: u64,
    /// Time elapsed since creation (milliseconds)
    pub elapsed_ms: u64,
    /// Queue position (1-based, when queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Priority level
    pub priority: QueryPriority,
}

// ============================================================================
// SearchJobStore trait
// ============================================================================

/// Pluggable storage backend for async search jobs.
///
/// All methods are async to support both in-memory (instant) and
/// Redis-backed (network I/O) implementations.
#[async_trait]
pub trait SearchJobStore: Send + Sync + std::fmt::Debug {
    /// Create a new Running job. Returns None if max jobs exceeded.
    ///
    /// `scope` (NAN-2096) is the effective source-scope deny-set the job will
    /// execute under. It is stamped on the job in the SAME write that creates
    /// it, so a job can never exist with an unknown execution scope.
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String>;

    /// Create a new Queued job with user/priority. Returns None if max jobs exceeded.
    ///
    /// See [`SearchJobStore::create`] for `scope`.
    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String>;

    /// Get a job by ID (without result payload to avoid large clones).
    async fn get(&self, job_id: &str) -> Option<SearchJob>;

    /// Get full job status including result.
    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse>;

    /// Get the ClickHouse query_id for a job.
    async fn get_query_id(&self, job_id: &str) -> Option<String>;

    /// Set the ClickHouse query_id for a job.
    async fn set_query_id(&self, job_id: &str, query_id: String);

    /// Mark a job as completed with results.
    async fn complete(&self, job_id: &str, result: SearchResponse);

    /// Mark a job as failed with an error message.
    async fn fail(&self, job_id: &str, error: String);

    /// Mark a job as cancelled.
    async fn cancel(&self, job_id: &str);

    /// Transition a queued job to Running.
    async fn start(&self, job_id: &str);

    /// Remove a job from the store.
    async fn remove(&self, job_id: &str) -> Option<SearchJob>;

    /// Update the queue position for a queued job.
    async fn set_queue_position(&self, job_id: &str, position: u32);

    /// List jobs for a specific user.
    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary>;

    /// List all jobs (admin view), filtered to those the viewer may see.
    ///
    /// NAN-2096/NAN-2109: the admin summary carries every principal's query
    /// preview, so the source-scope predicate lives INSIDE this call rather than
    /// in the handler — a caller cannot list a job whose result the poll route
    /// would refuse them. Pass an EMPTY `viewer_deny` for internal, non-user
    /// consumers (metrics, admission accounting): an empty deny-set is a subset
    /// of every stamp, so nothing is filtered out.
    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary>;

    /// Count of active (Running + Queued) jobs.
    async fn active_count(&self) -> usize;

    /// Total job count.
    async fn total_count(&self) -> usize;

    /// Periodic cleanup of expired/stale jobs.
    /// Default no-op (RedisJobStore uses native TTL expiry).
    async fn cleanup(&self) {}
}

// ============================================================================
// InMemoryJobStore (formerly SearchJobRegistry)
// ============================================================================

/// In-memory job store using DashMap for lock-free concurrent access.
/// Jobs are automatically cleaned up after TTL expires.
#[derive(Debug, Clone)]
pub struct InMemoryJobStore {
    jobs: Arc<DashMap<String, SearchJob>>,
}

impl Default for InMemoryJobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryJobStore {
    /// Create a new in-memory job store
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(DashMap::new()),
        }
    }

    /// Cleanup expired jobs
    pub fn cleanup_expired(&self) {
        let expired_ids: Vec<String> = self
            .jobs
            .iter()
            .filter(|r| r.value().is_expired())
            .map(|r| r.key().clone())
            .collect();

        for id in expired_ids {
            self.jobs.remove(&id);
            tracing::debug!("Cleaned up expired job: {}", id);
        }
    }
}

#[async_trait]
impl SearchJobStore for InMemoryJobStore {
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String> {
        self.cleanup_expired();

        if self.jobs.len() >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new(job_id.clone(), request, scope);
        self.jobs.insert(job_id.clone(), job);

        tracing::debug!("Created async search job: {}", job_id);
        Some(job_id)
    }

    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String> {
        self.cleanup_expired();

        if self.jobs.len() >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new_queued(job_id.clone(), request, user_id, priority, scope);
        self.jobs.insert(job_id.clone(), job);

        tracing::debug!(
            "Created queued search job: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Some(job_id)
    }

    async fn get(&self, job_id: &str) -> Option<SearchJob> {
        self.jobs.get(job_id).map(|r| {
            let job = r.value();
            SearchJob {
                id: job.id.clone(),
                status: job.status.clone(),
                query_id: job.query_id.clone(),
                user_id: job.user_id,
                priority: job.priority,
                queue_position: job.queue_position,
                created_at: job.created_at,
                completed_at: job.completed_at,
                request: job.request.clone(),
                result: None,
                error: job.error.clone(),
                scope_deny: job.scope_deny.clone(),
            }
        })
    }

    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse> {
        self.jobs.get(job_id).map(|r| {
            let job = r.value();
            SearchJobStatusResponse {
                job_id: job.id.clone(),
                status: job.status.clone(),
                progress: None,
                result: job.result.clone(),
                error: job.error.clone(),
                queue_position: job.queue_position,
                estimated_wait_seconds: None,
            }
        })
    }

    async fn get_query_id(&self, job_id: &str) -> Option<String> {
        self.jobs.get(job_id).map(|r| r.value().query_id.clone())
    }

    async fn set_query_id(&self, job_id: &str, query_id: String) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            job.query_id = query_id;
        }
    }

    async fn complete(&self, job_id: &str, result: SearchResponse) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            job.status = SearchJobStatus::Completed;
            job.completed_at = Some(Utc::now());
            job.result = Some(result);
            tracing::debug!("Job {} completed successfully", job_id);
        }
    }

    async fn fail(&self, job_id: &str, error: String) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            job.status = SearchJobStatus::Failed;
            job.completed_at = Some(Utc::now());
            job.error = Some(error);
            tracing::debug!("Job {} failed: {}", job_id, job.error.as_ref().unwrap());
        }
    }

    async fn cancel(&self, job_id: &str) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            job.status = SearchJobStatus::Cancelled;
            job.completed_at = Some(Utc::now());
            tracing::debug!("Job {} cancelled", job_id);
        }
    }

    async fn start(&self, job_id: &str) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            if job.status == SearchJobStatus::Queued {
                job.status = SearchJobStatus::Running;
                job.queue_position = None;
                tracing::debug!("Job {} transitioned Queued -> Running", job_id);
            }
        }
    }

    async fn remove(&self, job_id: &str) -> Option<SearchJob> {
        self.jobs.remove(job_id).map(|(_, job)| job)
    }

    async fn set_queue_position(&self, job_id: &str, position: u32) {
        if let Some(mut job) = self.jobs.get_mut(job_id) {
            job.queue_position = Some(position);
        }
    }

    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary> {
        self.jobs
            .iter()
            .filter(|r| r.value().user_id == Some(user_id))
            .map(|r| {
                let job = r.value();
                let query = truncate_query_preview(&job.request.query);
                SearchJobSummary {
                    job_id: job.id.clone(),
                    status: job.status.clone(),
                    query,
                    created_at_ms: job.created_at_ms(),
                    elapsed_ms: job.elapsed_ms(),
                    queue_position: job.queue_position,
                    priority: job.priority,
                }
            })
            .collect()
    }

    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary> {
        self.jobs
            .iter()
            .filter(|r| r.value().result_visible_under(viewer_deny))
            .map(|r| {
                let job = r.value();
                let query = truncate_query_preview(&job.request.query);
                AdminSearchJobSummary {
                    job_id: job.id.clone(),
                    status: job.status.clone(),
                    user_id: job.user_id.map(|u| u.to_string()),
                    query,
                    created_at_ms: job.created_at_ms(),
                    elapsed_ms: job.elapsed_ms(),
                    queue_position: job.queue_position,
                    priority: job.priority,
                }
            })
            .collect()
    }

    async fn active_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|r| r.status == SearchJobStatus::Running || r.status == SearchJobStatus::Queued)
            .count()
    }

    async fn total_count(&self) -> usize {
        self.jobs.len()
    }

    async fn cleanup(&self) {
        self.cleanup_expired();
    }
}

// ============================================================================
// Legacy type alias for backward compatibility
// ============================================================================

/// Backward-compatible alias — new code should use `InMemoryJobStore` directly.
pub type SearchJobRegistry = InMemoryJobStore;

// ============================================================================
// RedisJobStore
// ============================================================================

/// Redis-backed job store for active/active search deployments.
///
/// Key schema:
/// - `search:job:{job_id}` — Hash with job metadata fields
/// - `search:job:index:user:{user_id}` — Set of job_ids for a user
/// - `search:job:index:all` — Set of all job_ids
///
/// Results are stored gzip-compressed in the `result_gz` hash field.
/// TTL is set on completion (5 minutes, matching COMPLETED_JOB_TTL).
#[derive(Clone)]
pub struct RedisJobStore {
    conn: redis::aio::ConnectionManager,
}

impl std::fmt::Debug for RedisJobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisJobStore").finish()
    }
}

impl RedisJobStore {
    /// Create a new Redis job store from an existing ConnectionManager.
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self { conn }
    }

    /// Create a new Redis job store, connecting to the given URL.
    /// Returns None if connection fails (caller should fall back to InMemoryJobStore).
    pub async fn connect(redis_url: &str) -> Option<Self> {
        let client = match redis::Client::open(redis_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("RedisJobStore: failed to create Redis client: {}", e);
                return None;
            }
        };

        match redis::aio::ConnectionManager::new(client).await {
            Ok(conn) => {
                tracing::info!("RedisJobStore connected to {}", redis_url);
                Some(Self { conn })
            }
            Err(e) => {
                tracing::warn!("RedisJobStore: failed to connect to {}: {}", redis_url, e);
                None
            }
        }
    }

    fn job_key(job_id: &str) -> String {
        format!("search:job:{}", job_id)
    }

    fn user_index_key(user_id: &Uuid) -> String {
        format!("search:job:index:user:{}", user_id)
    }

    const ALL_INDEX_KEY: &'static str = "search:job:index:all";

    /// Compress a SearchResponse to gzip bytes for Redis storage.
    fn compress_result(result: &SearchResponse) -> Option<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let json = serde_json::to_vec(result).ok()?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&json).ok()?;
        encoder.finish().ok()
    }

    /// Decompress gzip bytes back to a SearchResponse.
    fn decompress_result(data: &[u8]) -> Option<SearchResponse> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut json_bytes = Vec::new();
        decoder.read_to_end(&mut json_bytes).ok()?;
        serde_json::from_slice(&json_bytes).ok()
    }

    /// NAN-2096: serialize the execution deny-set for the `scope_deny` hash
    /// field. An UNRESTRICTED scope round-trips as `"[]"`, which is distinct
    /// from a missing field (a pre-NAN-2096 job) — the reader must be able to
    /// tell "denied nothing" from "we don't know what this ran under".
    ///
    /// A serialization failure (unreachable for `BTreeSet<String>`) degrades to
    /// the EMPTY STRING, which decodes back as "unknown", not as `[]`. Falling
    /// back to `[]` would silently stamp a restricted job as unrestricted — the
    /// one direction that fails open.
    fn encode_scope_deny(scope: &ScopeSet) -> String {
        serde_json::to_string(scope.deny_set()).unwrap_or_default()
    }

    /// Inverse of [`Self::encode_scope_deny`]. An absent field (legacy job) or
    /// unparseable payload yields `None` — unknown provenance, which
    /// [`SearchJob::result_visible_under`] treats as fail-closed.
    fn decode_scope_deny(raw: Option<&str>) -> Option<BTreeSet<String>> {
        let raw = raw?;
        if raw.is_empty() {
            return None;
        }
        serde_json::from_str(raw).ok()
    }

    /// Apply completion TTL to job key and indexes.
    async fn set_completion_ttl(&self, job_id: &str, user_id: Option<&str>) {
        let mut conn = self.conn.clone();
        let ttl = COMPLETED_JOB_TTL.as_secs() as i64;

        let key = Self::job_key(job_id);
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(ttl)
            .query_async(&mut conn)
            .await;

        // Note: We don't expire the index sets themselves — they use SREM on cleanup.
        // Stale entries in the index are harmless (get() returns None for expired keys).
        // A background cleanup could SREM orphaned entries periodically if needed.
        let _ = user_id; // user index entries are cleaned lazily on list_for_user
    }
}

#[async_trait]
impl SearchJobStore for RedisJobStore {
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String> {
        let mut conn = self.conn.clone();

        // Check job limit
        let count: usize = redis::cmd("SCARD")
            .arg(Self::ALL_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        if count >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let now = Utc::now();
        let request_json = serde_json::to_string(&request).unwrap_or_default();

        let key = Self::job_key(&job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("running")
            .arg("query_id")
            .arg("")
            .arg("user_id")
            .arg("")
            .arg("priority")
            .arg(format!("{}", QueryPriority::Interactive))
            .arg("queue_position")
            .arg("")
            .arg("created_at_ms")
            .arg(now.timestamp_millis().to_string())
            .arg("completed_at_ms")
            .arg("")
            .arg("request_json")
            .arg(&request_json)
            .arg("error")
            .arg("")
            .arg("scope_deny")
            .arg(Self::encode_scope_deny(scope))
            .query_async(&mut conn)
            .await;

        // Add to global index
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(Self::ALL_INDEX_KEY)
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        tracing::debug!("Created async search job in Redis: {}", job_id);
        Some(job_id)
    }

    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String> {
        let mut conn = self.conn.clone();

        let count: usize = redis::cmd("SCARD")
            .arg(Self::ALL_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        if count >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let now = Utc::now();
        let request_json = serde_json::to_string(&request).unwrap_or_default();

        let key = Self::job_key(&job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("queued")
            .arg("query_id")
            .arg("")
            .arg("user_id")
            .arg(user_id.to_string())
            .arg("priority")
            .arg(format!("{}", priority))
            .arg("queue_position")
            .arg("")
            .arg("created_at_ms")
            .arg(now.timestamp_millis().to_string())
            .arg("completed_at_ms")
            .arg("")
            .arg("request_json")
            .arg(&request_json)
            .arg("error")
            .arg("")
            .arg("scope_deny")
            .arg(Self::encode_scope_deny(scope))
            .query_async(&mut conn)
            .await;

        // Add to global and user indexes
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(Self::ALL_INDEX_KEY)
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        let user_key = Self::user_index_key(&user_id);
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(&user_key)
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        tracing::debug!(
            "Created queued search job in Redis: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Some(job_id)
    }

    async fn get(&self, job_id: &str) -> Option<SearchJob> {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);

        // `Vec<Option<String>>`, NOT `Vec<String>`: redis-rs 1.x fails the WHOLE
        // conversion if any HMGET slot is nil, and `scope_deny` is absent on
        // jobs written before NAN-2096. Decoding into `Option` makes a missing
        // field a `None` slot instead of turning the entire `get()` into `None`
        // (which would break ownership resolution and cancel for legacy jobs).
        let fields: Vec<Option<String>> = redis::cmd("HMGET")
            .arg(&key)
            .arg("status")
            .arg("query_id")
            .arg("user_id")
            .arg("priority")
            .arg("queue_position")
            .arg("created_at_ms")
            .arg("completed_at_ms")
            .arg("request_json")
            .arg("error")
            .arg("scope_deny")
            .query_async(&mut conn)
            .await
            .ok()?;

        let field = |idx: usize| -> &str {
            fields
                .get(idx)
                .and_then(|v| v.as_deref())
                .unwrap_or_default()
        };

        if fields.len() < 9 || field(0).is_empty() {
            return None;
        }

        let status: SearchJobStatus = field(0).parse().ok()?;
        let query_id = field(1).to_string();
        let user_id = if field(2).is_empty() {
            None
        } else {
            Uuid::parse_str(field(2)).ok()
        };
        let priority: QueryPriority = field(3).parse().unwrap_or(QueryPriority::Interactive);
        let queue_position: Option<u32> = if field(4).is_empty() {
            None
        } else {
            field(4).parse().ok()
        };
        let created_at_ms: i64 = field(5).parse().unwrap_or(0);
        let created_at = DateTime::from_timestamp_millis(created_at_ms).unwrap_or_else(Utc::now);
        let completed_at = if field(6).is_empty() {
            None
        } else {
            field(6)
                .parse::<i64>()
                .ok()
                .and_then(DateTime::from_timestamp_millis)
        };
        let request: SearchRequest = serde_json::from_str(field(7)).ok()?;
        let error = if field(8).is_empty() {
            None
        } else {
            Some(field(8).to_string())
        };
        // Slot 9 goes through the same bounds-safe helper as every other slot;
        // "" (nil, or a short response) and a missing field both decode to
        // `None` — unknown provenance, which the read path fails closed on.
        let scope_deny = Self::decode_scope_deny(Some(field(9)));

        Some(SearchJob {
            id: job_id.to_string(),
            status,
            query_id,
            user_id,
            priority,
            queue_position,
            created_at,
            completed_at,
            request,
            result: None, // Don't load result here — use get_status() for that
            error,
            scope_deny,
        })
    }

    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse> {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);

        let fields: Vec<Vec<u8>> = redis::cmd("HMGET")
            .arg(&key)
            .arg("status")
            .arg("error")
            .arg("queue_position")
            .arg("result_gz")
            .query_async(&mut conn)
            .await
            .ok()?;

        if fields.len() < 4 || fields[0].is_empty() {
            return None;
        }

        let status_str = String::from_utf8_lossy(&fields[0]);
        let status: SearchJobStatus = status_str.parse().ok()?;
        let error_str = String::from_utf8_lossy(&fields[1]);
        let error = if error_str.is_empty() {
            None
        } else {
            Some(error_str.to_string())
        };
        let qp_str = String::from_utf8_lossy(&fields[2]);
        let queue_position: Option<u32> = if qp_str.is_empty() {
            None
        } else {
            qp_str.parse().ok()
        };

        let result = if fields[3].is_empty() {
            None
        } else {
            Self::decompress_result(&fields[3])
        };

        Some(SearchJobStatusResponse {
            job_id: job_id.to_string(),
            status,
            progress: None,
            result,
            error,
            queue_position,
            estimated_wait_seconds: None,
        })
    }

    async fn get_query_id(&self, job_id: &str) -> Option<String> {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let qid: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("query_id")
            .query_async(&mut conn)
            .await
            .ok()?;
        qid.filter(|s| !s.is_empty())
    }

    async fn set_query_id(&self, job_id: &str, query_id: String) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("query_id")
            .arg(&query_id)
            .query_async(&mut conn)
            .await;
    }

    async fn complete(&self, job_id: &str, result: SearchResponse) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        // Compress result for storage
        let result_gz = Self::compress_result(&result).unwrap_or_default();

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("completed")
            .arg("completed_at_ms")
            .arg(&now_ms)
            .arg("result_gz")
            .arg(&result_gz[..])
            .query_async(&mut conn)
            .await;

        // Get user_id for TTL cleanup
        let user_id: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("user_id")
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();

        self.set_completion_ttl(job_id, user_id.as_deref()).await;
        tracing::debug!("Job {} completed successfully (Redis)", job_id);
    }

    async fn fail(&self, job_id: &str, error: String) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("failed")
            .arg("completed_at_ms")
            .arg(&now_ms)
            .arg("error")
            .arg(&error)
            .query_async(&mut conn)
            .await;

        self.set_completion_ttl(job_id, None).await;
        tracing::debug!("Job {} failed (Redis): {}", job_id, error);
    }

    async fn cancel(&self, job_id: &str) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("cancelled")
            .arg("completed_at_ms")
            .arg(&now_ms)
            .query_async(&mut conn)
            .await;

        self.set_completion_ttl(job_id, None).await;
        tracing::debug!("Job {} cancelled (Redis)", job_id);
    }

    async fn start(&self, job_id: &str) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);

        // Only transition if currently queued
        let current: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("status")
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();

        if current.as_deref() == Some("queued") {
            let _: Result<(), _> = redis::cmd("HSET")
                .arg(&key)
                .arg("status")
                .arg("running")
                .arg("queue_position")
                .arg("")
                .query_async(&mut conn)
                .await;
            tracing::debug!("Job {} transitioned Queued -> Running (Redis)", job_id);
        }
    }

    async fn remove(&self, job_id: &str) -> Option<SearchJob> {
        let job = self.get(job_id).await;

        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);

        // Remove from indexes
        let _: Result<(), _> = redis::cmd("SREM")
            .arg(Self::ALL_INDEX_KEY)
            .arg(job_id)
            .query_async(&mut conn)
            .await;

        if let Some(ref j) = job {
            if let Some(uid) = &j.user_id {
                let _: Result<(), _> = redis::cmd("SREM")
                    .arg(Self::user_index_key(uid))
                    .arg(job_id)
                    .query_async(&mut conn)
                    .await;
            }
        }

        // Delete the hash
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;

        job
    }

    async fn set_queue_position(&self, job_id: &str, position: u32) {
        let mut conn = self.conn.clone();
        let key = Self::job_key(job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("queue_position")
            .arg(position.to_string())
            .query_async(&mut conn)
            .await;
    }

    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary> {
        let mut conn = self.conn.clone();
        let user_key = Self::user_index_key(&user_id);

        let job_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_key)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();

        let mut summaries = Vec::new();
        for jid in job_ids {
            if let Some(job) = self.get(&jid).await {
                let query = truncate_query_preview(&job.request.query);
                let created_at_ms = job.created_at_ms();
                let elapsed_ms = job.elapsed_ms();
                summaries.push(SearchJobSummary {
                    job_id: job.id,
                    status: job.status,
                    query,
                    created_at_ms,
                    elapsed_ms,
                    queue_position: job.queue_position,
                    priority: job.priority,
                });
            } else {
                // Stale index entry — clean up
                let _: Result<(), _> = redis::cmd("SREM")
                    .arg(&user_key)
                    .arg(&jid)
                    .query_async(&mut conn)
                    .await;
            }
        }
        summaries
    }

    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary> {
        let mut conn = self.conn.clone();

        let job_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(Self::ALL_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();

        let mut summaries = Vec::new();
        for jid in job_ids {
            if let Some(job) = self.get(&jid).await {
                // `get` already decoded the stamp, so the filter is free.
                if !job.result_visible_under(viewer_deny) {
                    continue;
                }
                let query = truncate_query_preview(&job.request.query);
                let created_at_ms = job.created_at_ms();
                let elapsed_ms = job.elapsed_ms();
                summaries.push(AdminSearchJobSummary {
                    job_id: job.id,
                    status: job.status,
                    user_id: job.user_id.map(|u| u.to_string()),
                    query,
                    created_at_ms,
                    elapsed_ms,
                    queue_position: job.queue_position,
                    priority: job.priority,
                });
            } else {
                // Stale index entry — clean up
                let _: Result<(), _> = redis::cmd("SREM")
                    .arg(Self::ALL_INDEX_KEY)
                    .arg(&jid)
                    .query_async(&mut conn)
                    .await;
            }
        }
        summaries
    }

    async fn active_count(&self) -> usize {
        // For Redis, we iterate all jobs and count active ones.
        // In practice this set is small (<1000 by MAX_JOBS limit).
        // Internal accounting, not a user-facing read: an EMPTY viewer deny-set
        // is a subset of every stamp, so no job is filtered out of the count.
        let all = self.list_all(&BTreeSet::new()).await;
        all.iter()
            .filter(|j| j.status == SearchJobStatus::Running || j.status == SearchJobStatus::Queued)
            .count()
    }

    async fn total_count(&self) -> usize {
        let mut conn = self.conn.clone();
        redis::cmd("SCARD")
            .arg(Self::ALL_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::types::TimeRangeInput;

    /// NAN-2010 (F12/F15/F16/F17/F25): the job-list preview must not panic when
    /// the stored query has a multibyte character straddling the truncation
    /// offset. Before the fix `&query[..97]` panicked, breaking the admin
    /// all-jobs endpoint for every admin (cross-user DoS).
    #[test]
    fn truncate_query_preview_never_panics_on_multibyte_boundary() {
        // 95 ASCII + two 3-byte chars => byte 97 lands inside the first '€'.
        let q = format!("{}€€", "a".repeat(95));
        assert!(q.len() > 100 && !q.is_char_boundary(97));
        let preview = truncate_query_preview(&q);
        assert!(preview.ends_with("..."));
        assert!(preview.len() <= 100 + 3);

        // A 4-byte emoji straddling the offset must also be safe.
        let q2 = format!("{}😀ok", "b".repeat(96));
        let _ = truncate_query_preview(&q2); // must not panic

        // Short queries are returned verbatim.
        assert_eq!(truncate_query_preview("short"), "short");
    }

    fn make_test_request() -> SearchRequest {
        SearchRequest {
            query: "test".to_string(),
            time_range: TimeRangeInput {
                start: Utc::now(),
                end: Utc::now(),
            },
            limit: None,
            offset: None,
            include_sql: None,
            skip_histogram: false,
            skip_field_stats: false,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        }
    }

    #[tokio::test]
    async fn test_create_and_get_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Running);
        assert!(job.result.is_none());
        assert!(job.error.is_none());
    }

    #[tokio::test]
    async fn test_complete_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        let result = SearchResponse::empty();
        store.complete(&job_id, result).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Completed);
        assert!(status.result.is_some());
    }

    #[tokio::test]
    async fn test_fail_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store.fail(&job_id, "Test error".to_string()).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Failed);
        assert_eq!(status.error.as_ref().unwrap(), "Test error");
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store.cancel(&job_id).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_set_query_id() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store
            .set_query_id(&job_id, "ch-query-123".to_string())
            .await;

        let query_id = store.get_query_id(&job_id).await.unwrap();
        assert_eq!(query_id, "ch-query-123");
    }

    #[tokio::test]
    async fn test_create_queued_and_start() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Queued);
        assert_eq!(job.user_id, Some(user_id));
        assert_eq!(job.priority, QueryPriority::Interactive);

        // Transition to Running
        store.start(&job_id).await;
        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Running);
    }

    #[tokio::test]
    async fn test_list_for_user() {
        let store = InMemoryJobStore::new();
        let user1 = Uuid::now_v7();
        let user2 = Uuid::now_v7();

        let _j1 = store
            .create_queued(
                make_test_request(),
                user1,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();
        let _j2 = store
            .create_queued(
                make_test_request(),
                user1,
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();
        let _j3 = store
            .create_queued(
                make_test_request(),
                user2,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let user1_jobs = store.list_for_user(user1).await;
        assert_eq!(user1_jobs.len(), 2);

        let user2_jobs = store.list_for_user(user2).await;
        assert_eq!(user2_jobs.len(), 1);
    }

    #[tokio::test]
    async fn test_set_queue_position() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        store.set_queue_position(&job_id, 3).await;
        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.queue_position, Some(3));
    }

    // ========================================================================
    // NAN-2096 — async results must not survive source-scope revocation
    // ========================================================================

    fn deny(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn job_stamped_with(scope: &[&str]) -> SearchJob {
        SearchJob::new_queued(
            "job-1".to_string(),
            make_test_request(),
            Uuid::now_v7(),
            QueryPriority::Interactive,
            &ScopeSet::from_denied(deny(scope)),
        )
    }

    /// The reported repro: a job runs while `windows_sysmon` is visible, then the
    /// source is restricted. Polling the completed job must no longer expose it.
    #[test]
    fn scope_narrowed_after_submission_hides_the_result() {
        let job = job_stamped_with(&["audit"]);
        // Same scope as submission → still readable.
        assert!(job.result_visible_under(&deny(&["audit"])));
        // `windows_sysmon` newly restricted → the snapshot may contain it.
        assert!(!job.result_visible_under(&deny(&["audit", "windows_sysmon"])));
    }

    /// Widening the caller's visibility is always safe — the stored result can
    /// only under-report relative to what they may now see.
    #[test]
    fn scope_widened_after_submission_still_returns_the_result() {
        let job = job_stamped_with(&["audit", "insider_threat"]);
        assert!(job.result_visible_under(&deny(&["audit"])));
        assert!(job.result_visible_under(&BTreeSet::new()));
    }

    /// A result built from several sources fails closed as soon as ONE of them
    /// could now be denied — results carry no per-row source manifest, so there
    /// is nothing to re-filter against.
    #[test]
    fn mixed_source_result_fails_closed_on_one_new_denial() {
        let job = job_stamped_with(&[]);
        assert!(job.result_visible_under(&BTreeSet::new()));
        assert!(!job.result_visible_under(&deny(&["aws_cloudtrail"])));
    }

    /// Swapping one denied source for another is NOT a subset relation: the
    /// newly denied source could be in the result even though the deny-set is
    /// the same size.
    #[test]
    fn equal_size_but_different_denial_fails_closed() {
        let job = job_stamped_with(&["insider_threat"]);
        assert!(!job.result_visible_under(&deny(&["windows_sysmon"])));
    }

    /// Legacy jobs (written before the stamp existed) have unknown provenance.
    /// Unknown is never "unrestricted": only a caller denied nothing at all may
    /// read them.
    #[test]
    fn unstamped_legacy_job_fails_closed_for_restricted_callers() {
        let mut job = job_stamped_with(&[]);
        job.scope_deny = None;
        assert!(!job.result_visible_under(&deny(&["audit"])));
        assert!(!job.result_visible_under(&deny(&["windows_sysmon"])));
        assert!(job.result_visible_under(&BTreeSet::new()));
    }

    /// The stamp is written by the CREATING call, so no job can exist without
    /// one — verified through the store rather than the constructor.
    #[tokio::test]
    async fn in_memory_store_stamps_the_execution_scope_at_creation() {
        let store = InMemoryJobStore::new();
        let scope = ScopeSet::from_denied(deny(&["audit", "insider_threat"]));

        let queued = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &scope,
            )
            .await
            .unwrap();
        let job = store.get(&queued).await.unwrap();
        assert_eq!(job.scope_deny.as_ref(), Some(&deny(&["audit", "insider_threat"])));
        assert!(!job.result_visible_under(&deny(&["audit", "insider_threat", "windows_sysmon"])));

        // The non-queued constructor stamps identically.
        let running = store
            .create(make_test_request(), &scope)
            .await
            .unwrap();
        let job = store.get(&running).await.unwrap();
        assert_eq!(job.scope_deny.as_ref(), Some(&deny(&["audit", "insider_threat"])));
    }

    /// NAN-2109 + NAN-2096: the admin list carries every principal's query
    /// preview, so the scope predicate lives INSIDE `list_all` — an admin cannot
    /// enumerate a job whose result the poll route would refuse them. Internal
    /// consumers pass an empty deny-set and still see everything.
    #[tokio::test]
    async fn admin_list_hides_jobs_the_viewer_could_not_poll() {
        let store = InMemoryJobStore::new();
        let visible = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &ScopeSet::from_denied(deny(&["audit", "windows_sysmon"])),
            )
            .await
            .unwrap();
        let hidden = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &ScopeSet::from_denied(deny(&["audit"])),
            )
            .await
            .unwrap();

        // Viewer denied `windows_sysmon` sees only the job that already
        // excluded it.
        let viewer = deny(&["audit", "windows_sysmon"]);
        let ids: Vec<String> = store
            .list_all(&viewer)
            .await
            .into_iter()
            .map(|j| j.job_id)
            .collect();
        assert!(ids.contains(&visible));
        assert!(!ids.contains(&hidden));

        // Internal / unrestricted consumers (admission accounting) see all.
        assert_eq!(store.list_all(&BTreeSet::new()).await.len(), 2);
        assert_eq!(store.active_count().await, 2);
    }

    /// Redis parity: an UNRESTRICTED scope must round-trip as "denied nothing",
    /// distinct from a legacy row where the hash field is simply absent. If
    /// these collapsed, either every unrestricted job would fail closed or every
    /// legacy job would be treated as unrestricted.
    #[test]
    fn redis_scope_encoding_distinguishes_unrestricted_from_missing() {
        let unrestricted = RedisJobStore::encode_scope_deny(&ScopeSet::unrestricted());
        assert_eq!(unrestricted, "[]");
        assert_eq!(
            RedisJobStore::decode_scope_deny(Some(&unrestricted)),
            Some(BTreeSet::new())
        );

        let restricted =
            RedisJobStore::encode_scope_deny(&ScopeSet::from_denied(deny(&["audit", "zeek"])));
        assert_eq!(
            RedisJobStore::decode_scope_deny(Some(&restricted)),
            Some(deny(&["audit", "zeek"]))
        );

        // Legacy row: field absent (nil → None) or empty. Both are "unknown".
        assert_eq!(RedisJobStore::decode_scope_deny(None), None);
        assert_eq!(RedisJobStore::decode_scope_deny(Some("")), None);
        // Corrupt payload is unknown too, never silently unrestricted.
        assert_eq!(RedisJobStore::decode_scope_deny(Some("{not json")), None);

        // A restricted scope must never encode to the unrestricted stamp. The
        // encoder's `unwrap_or_default()` failure path yields "" (which decodes
        // to `None`/unknown) precisely so that a serialization failure cannot
        // downgrade a restricted job to "denied nothing" — the one fail-open
        // direction. Serialization of `BTreeSet<String>` cannot actually fail,
        // so the branch is asserted by construction rather than executed.
        assert_ne!(restricted, "[]");
        assert_ne!(RedisJobStore::encode_scope_deny(&ScopeSet::unrestricted()), "");
    }

    #[tokio::test]
    async fn test_queued_status_in_response() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Queued);
    }
}
