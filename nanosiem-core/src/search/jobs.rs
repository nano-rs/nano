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
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::admission::QueryPriority;
use super::types::{SearchRequest, SearchResponse};

/// Maximum number of concurrent jobs
const MAX_JOBS: usize = 1000;

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
}

impl SearchJob {
    /// Create a new running job
    pub fn new(id: String, request: SearchRequest) -> Self {
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
        }
    }

    /// Create a new job in Queued state with user and priority
    pub fn new_queued(
        id: String,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
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
    async fn create(&self, request: SearchRequest) -> Option<String>;

    /// Create a new Queued job with user/priority. Returns None if max jobs exceeded.
    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
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

    /// List all jobs (admin view).
    async fn list_all(&self) -> Vec<AdminSearchJobSummary>;

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
    async fn create(&self, request: SearchRequest) -> Option<String> {
        self.cleanup_expired();

        if self.jobs.len() >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new(job_id.clone(), request);
        self.jobs.insert(job_id.clone(), job);

        tracing::debug!("Created async search job: {}", job_id);
        Some(job_id)
    }

    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
    ) -> Option<String> {
        self.cleanup_expired();

        if self.jobs.len() >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new_queued(job_id.clone(), request, user_id, priority);
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
                let query = if job.request.query.len() > 100 {
                    format!("{}...", &job.request.query[..97])
                } else {
                    job.request.query.clone()
                };
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

    async fn list_all(&self) -> Vec<AdminSearchJobSummary> {
        self.jobs
            .iter()
            .map(|r| {
                let job = r.value();
                let query = if job.request.query.len() > 100 {
                    format!("{}...", &job.request.query[..97])
                } else {
                    job.request.query.clone()
                };
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
    async fn create(&self, request: SearchRequest) -> Option<String> {
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

        let fields: Vec<String> = redis::cmd("HMGET")
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
            .query_async(&mut conn)
            .await
            .ok()?;

        if fields.len() < 9 || fields[0].is_empty() {
            return None;
        }

        let status: SearchJobStatus = fields[0].parse().ok()?;
        let query_id = fields[1].clone();
        let user_id = if fields[2].is_empty() {
            None
        } else {
            Uuid::parse_str(&fields[2]).ok()
        };
        let priority: QueryPriority = fields[3].parse().unwrap_or(QueryPriority::Interactive);
        let queue_position: Option<u32> = if fields[4].is_empty() {
            None
        } else {
            fields[4].parse().ok()
        };
        let created_at_ms: i64 = fields[5].parse().unwrap_or(0);
        let created_at = DateTime::from_timestamp_millis(created_at_ms).unwrap_or_else(Utc::now);
        let completed_at = if fields[6].is_empty() {
            None
        } else {
            fields[6]
                .parse::<i64>()
                .ok()
                .and_then(DateTime::from_timestamp_millis)
        };
        let request: SearchRequest = serde_json::from_str(&fields[7]).ok()?;
        let error = if fields[8].is_empty() {
            None
        } else {
            Some(fields[8].clone())
        };

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
                let query = if job.request.query.len() > 100 {
                    format!("{}...", &job.request.query[..97])
                } else {
                    job.request.query.clone()
                };
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

    async fn list_all(&self) -> Vec<AdminSearchJobSummary> {
        let mut conn = self.conn.clone();

        let job_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(Self::ALL_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();

        let mut summaries = Vec::new();
        for jid in job_ids {
            if let Some(job) = self.get(&jid).await {
                let query = if job.request.query.len() > 100 {
                    format!("{}...", &job.request.query[..97])
                } else {
                    job.request.query.clone()
                };
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
        let all = self.list_all().await;
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
        let job_id = store.create(make_test_request()).await.unwrap();

        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Running);
        assert!(job.result.is_none());
        assert!(job.error.is_none());
    }

    #[tokio::test]
    async fn test_complete_job() {
        let store = InMemoryJobStore::new();
        let job_id = store.create(make_test_request()).await.unwrap();

        let result = SearchResponse::empty();
        store.complete(&job_id, result).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Completed);
        assert!(status.result.is_some());
    }

    #[tokio::test]
    async fn test_fail_job() {
        let store = InMemoryJobStore::new();
        let job_id = store.create(make_test_request()).await.unwrap();

        store.fail(&job_id, "Test error".to_string()).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Failed);
        assert_eq!(status.error.as_ref().unwrap(), "Test error");
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let store = InMemoryJobStore::new();
        let job_id = store.create(make_test_request()).await.unwrap();

        store.cancel(&job_id).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_set_query_id() {
        let store = InMemoryJobStore::new();
        let job_id = store.create(make_test_request()).await.unwrap();

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
            .create_queued(make_test_request(), user_id, QueryPriority::Interactive)
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
            .create_queued(make_test_request(), user1, QueryPriority::Interactive)
            .await
            .unwrap();
        let _j2 = store
            .create_queued(make_test_request(), user1, QueryPriority::Analytics)
            .await
            .unwrap();
        let _j3 = store
            .create_queued(make_test_request(), user2, QueryPriority::Interactive)
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
            .create_queued(make_test_request(), user_id, QueryPriority::Interactive)
            .await
            .unwrap();

        store.set_queue_position(&job_id, 3).await;
        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.queue_position, Some(3));
    }

    #[tokio::test]
    async fn test_queued_status_in_response() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(make_test_request(), user_id, QueryPriority::Interactive)
            .await
            .unwrap();

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Queued);
    }
}
