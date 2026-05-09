// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search query admission control
//!
//! Priority-based admission controller using either:
//! - **Redis atomic counters** for cluster-wide limits (active/active deployments)
//! - **Local atomics** as fallback (single-instance or Redis unavailable)
//!
//! Detection/NRT queries bypass the queue entirely. Interactive/Analytics queries
//! are subject to global and per-user concurrency limits with priority-based queuing.

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{oneshot, Mutex, Notify};

/// Priority level for search queries (lower number = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryPriority {
    /// Detection rule execution — always admitted, bypasses queue
    Detection,
    /// Near-realtime detection — always admitted, bypasses queue
    NearRealtime,
    /// Interactive analyst search — subject to limits
    Interactive,
    /// Analytics / threat hunting — subject to limits, lowest priority
    Analytics,
}

impl QueryPriority {
    /// Numeric priority (lower = higher priority)
    fn ordinal(&self) -> u8 {
        match self {
            QueryPriority::Detection => 0,
            QueryPriority::NearRealtime => 1,
            QueryPriority::Interactive => 2,
            QueryPriority::Analytics => 3,
        }
    }

    /// Whether this priority bypasses admission control entirely
    pub fn bypasses_queue(&self) -> bool {
        matches!(self, QueryPriority::Detection | QueryPriority::NearRealtime)
    }

    /// Small delay applied before a request actually attempts to claim an
    /// admission slot. Lets higher-priority requests win the initial-burst
    /// race when many panels fire simultaneously (NAN-709).
    ///
    /// NAN-708 already orders the *queue* by priority — anything that has
    /// to wait for a slot drains cheap-first. But the very first N
    /// requests to reach `acquire()` get admitted on a first-come basis
    /// (network-timing race), so 1-2 Analytics-priority panels can sneak
    /// into the initial admit burst and run alongside Interactive panels.
    /// This delay shifts the Analytics arrivals so Interactive ones reach
    /// the gate first deterministically.
    ///
    /// Returns `None` for queue-bypassing priorities (Detection/NRT) since
    /// they don't go through the admission controller anyway, and for
    /// Interactive (the priority we want to win the race).
    pub fn admit_delay(&self) -> Option<std::time::Duration> {
        match self {
            QueryPriority::Detection | QueryPriority::NearRealtime => None,
            QueryPriority::Interactive => None,
            QueryPriority::Analytics => Some(std::time::Duration::from_millis(250)),
        }
    }

    /// Returns ClickHouse query settings for this priority level
    pub fn to_ch_settings(&self) -> ClickHouseQuerySettings {
        match self {
            QueryPriority::Detection | QueryPriority::NearRealtime => ClickHouseQuerySettings {
                max_execution_time: 30,
                max_memory_usage_bytes: 5 * 1024 * 1024 * 1024, // 5 GB
                max_threads: 8,
                priority: 1,
                queue_max_wait_ms: 5000,
            },
            QueryPriority::Interactive => ClickHouseQuerySettings {
                max_execution_time: 300,
                max_memory_usage_bytes: 20 * 1024 * 1024 * 1024, // 20 GB
                max_threads: 16,
                priority: 3,
                queue_max_wait_ms: 60000,
            },
            QueryPriority::Analytics => ClickHouseQuerySettings {
                max_execution_time: 3600,
                max_memory_usage_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
                max_threads: 32,
                priority: 5,
                queue_max_wait_ms: 120000,
            },
        }
    }
}

impl std::fmt::Display for QueryPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryPriority::Detection => write!(f, "detection"),
            QueryPriority::NearRealtime => write!(f, "near_realtime"),
            QueryPriority::Interactive => write!(f, "interactive"),
            QueryPriority::Analytics => write!(f, "analytics"),
        }
    }
}

impl std::str::FromStr for QueryPriority {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "detection" => Ok(Self::Detection),
            "near_realtime" => Ok(Self::NearRealtime),
            "interactive" => Ok(Self::Interactive),
            "analytics" => Ok(Self::Analytics),
            _ => Err(format!("unknown priority: {}", s)),
        }
    }
}

/// Per-query ClickHouse settings applied via `.with_option()`
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClickHouseQuerySettings {
    /// Maximum execution time in seconds
    pub max_execution_time: u32,
    /// Maximum memory usage in bytes
    pub max_memory_usage_bytes: u64,
    /// Maximum parallel threads
    pub max_threads: u32,
    /// ClickHouse scheduler priority (1=highest)
    pub priority: u32,
    /// ClickHouse-side queue wait timeout in milliseconds
    pub queue_max_wait_ms: u32,
}

/// Configuration for the admission controller
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdmissionConfig {
    /// Maximum concurrent ad-hoc queries (Interactive + Analytics)
    pub global_adhoc_limit: u32,
    /// Maximum concurrent queries per user
    pub per_user_limit: u32,
    /// Maximum queue depth before rejecting new queries
    pub max_queue_depth: u32,
    /// Queue timeout in milliseconds
    pub queue_timeout_ms: u64,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            global_adhoc_limit: 30,
            per_user_limit: 5,
            max_queue_depth: 100,
            // NAN-714: bumped from 120_000 (2 min) to 300_000 (5 min) to
            // match the Interactive priority's `max_execution_time = 300s`.
            // Previously a request could be rejected at the admission gate
            // while CH would have happily run an equivalent query for the
            // full 5 minutes. Aligning lets requests under contention wait
            // long enough for a slot to free up via natural query
            // completion.
            queue_timeout_ms: 300_000,
        }
    }
}

/// Errors returned by the admission controller
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("Per-user query limit exceeded ({limit} concurrent queries)")]
    UserLimitExceeded { limit: u32 },
    #[error("Search queue is full ({depth} queries waiting)")]
    QueueFull { depth: u32 },
    #[error("Search queue timeout after {timeout_ms}ms")]
    QueueTimeout { timeout_ms: u64 },
    #[error("Query cancelled while queued")]
    Cancelled,
}

// ============================================================================
// Redis counter keys
// ============================================================================

const REDIS_GLOBAL_KEY: &str = "search:admission:active";

fn redis_user_key(user_id: &uuid::Uuid) -> String {
    format!("search:admission:user:{}", user_id)
}

/// TTL for per-user counters (auto-cleanup if process crashes without decrementing).
/// Set slightly longer than the max query execution time (1h analytics + buffer).
const REDIS_USER_KEY_TTL_SECS: i64 = 7200;

/// Lua script for atomic check-and-increment.
///
/// KEYS[1] = global key, KEYS[2] = user key
/// ARGV[1] = global limit, ARGV[2] = per-user limit, ARGV[3] = user key TTL
///
/// Returns:
///   1 = admitted
///   -1 = global limit exceeded (should enqueue)
///   -2 = per-user limit exceeded (reject)
const ACQUIRE_LUA: &str = r#"
local global_key = KEYS[1]
local user_key = KEYS[2]
local global_limit = tonumber(ARGV[1])
local user_limit = tonumber(ARGV[2])
local user_ttl = tonumber(ARGV[3])

-- Check per-user limit first (hard reject, not queueable)
local user_count = tonumber(redis.call('GET', user_key) or '0')
if user_count >= user_limit then
    return -2
end

-- Check global limit
local global_count = tonumber(redis.call('GET', global_key) or '0')
if global_count >= global_limit then
    return -1
end

-- Admit: increment both counters atomically
redis.call('INCR', global_key)
redis.call('INCR', user_key)
redis.call('EXPIRE', user_key, user_ttl)
return 1
"#;

// ============================================================================
// AdmissionPermit
// ============================================================================

/// RAII guard — dropping it frees an admission slot and wakes the next queued search.
///
/// Supports both local atomics and Redis counters. When Redis is configured,
/// `drop` spawns a fire-and-forget task to DECR the Redis counters.
pub struct AdmissionPermit {
    user_id: uuid::Uuid,
    bypassed: bool,
    // Local counters (always updated for metrics/gauges)
    active_adhoc: Arc<AtomicU32>,
    per_user_active: Arc<DashMap<uuid::Uuid, u32>>,
    slot_available: Arc<Notify>,
    // Optional Redis connection for cluster-wide counters
    redis_conn: Option<redis::aio::ConnectionManager>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if self.bypassed {
            return;
        }

        // Always update local counters (for gauges and single-instance fallback)
        let new_active = self.active_adhoc.fetch_sub(1, AtomicOrdering::SeqCst) - 1;
        if let Some(mut count) = self.per_user_active.get_mut(&self.user_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.per_user_active.remove(&self.user_id);
            }
        }
        gauge!("nanosiem_search_active_queries").set(new_active as f64);
        self.slot_available.notify_one();

        // Decrement Redis counters if configured (fire-and-forget)
        if let Some(conn) = self.redis_conn.take() {
            let user_id = self.user_id;
            tokio::spawn(async move {
                let mut conn = conn;
                let user_key = redis_user_key(&user_id);

                // DECR global counter (floor at 0 to prevent negative drift)
                let global_val: i64 = redis::cmd("DECR")
                    .arg(REDIS_GLOBAL_KEY)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if global_val < 0 {
                    let _: Result<(), _> = redis::cmd("SET")
                        .arg(REDIS_GLOBAL_KEY)
                        .arg(0)
                        .query_async(&mut conn)
                        .await;
                }

                // DECR per-user counter
                let user_val: i64 = redis::cmd("DECR")
                    .arg(&user_key)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if user_val <= 0 {
                    let _: Result<(), _> = redis::cmd("DEL")
                        .arg(&user_key)
                        .query_async(&mut conn)
                        .await;
                }
            });
        }
    }
}

/// A queued search waiting for admission
struct QueuedSearch {
    job_id: String,
    priority: QueryPriority,
    enqueued_at: Instant,
    /// Sender to notify when admitted
    tx: oneshot::Sender<Result<(), AdmissionError>>,
}

impl PartialEq for QueuedSearch {
    fn eq(&self, other: &Self) -> bool {
        self.priority.ordinal() == other.priority.ordinal() && self.enqueued_at == other.enqueued_at
    }
}

impl Eq for QueuedSearch {}

impl PartialOrd for QueuedSearch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedSearch {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority (lower ordinal) first, then older first (FIFO within same priority)
        other
            .priority
            .ordinal()
            .cmp(&self.priority.ordinal())
            .then_with(|| other.enqueued_at.cmp(&self.enqueued_at))
    }
}

/// Admission statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdmissionStats {
    /// Number of active ad-hoc queries
    pub active_adhoc: u32,
    /// Number of queued queries
    pub queued: u32,
    /// Per-user active query counts
    pub per_user_counts: Vec<(String, u32)>,
}

/// Priority-based admission controller for search queries.
///
/// When a Redis connection is provided, limits are enforced globally across
/// all instances via atomic Lua scripts. Local atomics are always maintained
/// as a fallback and for Prometheus gauges.
pub struct AdmissionController {
    config: Mutex<AdmissionConfig>,
    // Local counters (always maintained for gauges + fallback)
    active_adhoc: Arc<AtomicU32>,
    per_user_active: Arc<DashMap<uuid::Uuid, u32>>,
    queue: Mutex<BinaryHeap<QueuedSearch>>,
    slot_available: Arc<Notify>,
    // Optional Redis connection for cluster-wide counters
    redis_conn: Mutex<Option<redis::aio::ConnectionManager>>,
}

impl AdmissionController {
    /// Create a new admission controller with the given configuration
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config: Mutex::new(config),
            active_adhoc: Arc::new(AtomicU32::new(0)),
            per_user_active: Arc::new(DashMap::new()),
            queue: Mutex::new(BinaryHeap::new()),
            slot_available: Arc::new(Notify::new()),
            redis_conn: Mutex::new(None),
        }
    }

    /// Set the Redis connection for cluster-wide admission limits.
    /// When set, limits are enforced globally via Redis atomic counters.
    /// When not set (or Redis becomes unavailable), falls back to local atomics.
    pub async fn set_redis(&self, conn: redis::aio::ConnectionManager) {
        *self.redis_conn.lock().await = Some(conn);
        tracing::info!("Admission controller: Redis cluster-wide limits enabled");
    }

    /// Acquire an admission permit for executing a search query.
    ///
    /// - Detection/NRT: Always admitted immediately (bypasses queue).
    /// - Interactive/Analytics: Subject to per-user and global limits.
    ///   If limits are full, the query is enqueued with priority ordering.
    pub async fn acquire(
        &self,
        job_id: &str,
        user_id: uuid::Uuid,
        priority: QueryPriority,
    ) -> Result<AdmissionPermit, AdmissionError> {
        // Detection/NRT always bypass
        if priority.bypasses_queue() {
            counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                .increment(1);
            return Ok(AdmissionPermit {
                user_id,
                bypassed: true,
                active_adhoc: self.active_adhoc.clone(),
                per_user_active: self.per_user_active.clone(),
                slot_available: self.slot_available.clone(),
                redis_conn: None,
            });
        }

        // Try immediate admission
        if let Some(permit) = self.try_admit(user_id).await? {
            counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                .increment(1);
            self.update_gauges().await;
            return Ok(permit);
        }

        // Enqueue and wait
        let (tx, rx) = oneshot::channel();
        let config = self.config.lock().await;
        let queue_timeout_ms = config.queue_timeout_ms;
        let max_queue_depth = config.max_queue_depth;
        drop(config);

        let enqueued_at = Instant::now();
        {
            let mut queue = self.queue.lock().await;
            if queue.len() >= max_queue_depth as usize {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_full")
                    .increment(1);
                return Err(AdmissionError::QueueFull {
                    depth: max_queue_depth,
                });
            }
            queue.push(QueuedSearch {
                job_id: job_id.to_string(),
                priority,
                enqueued_at,
                tx,
            });
            counter!("nanosiem_search_jobs_queued_total").increment(1);
            gauge!("nanosiem_search_queue_depth").set(queue.len() as f64);
        }

        // Wait for slot with timeout
        match tokio::time::timeout(std::time::Duration::from_millis(queue_timeout_ms), rx).await {
            Ok(Ok(Ok(()))) => {
                // We were admitted by drain_queue — slot already counted
                let wait_secs = enqueued_at.elapsed().as_secs_f64();
                histogram!("nanosiem_search_queue_wait_seconds").record(wait_secs);
                counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                    .increment(1);
                self.update_gauges().await;
                Ok(AdmissionPermit {
                    user_id,
                    bypassed: false,
                    active_adhoc: self.active_adhoc.clone(),
                    per_user_active: self.per_user_active.clone(),
                    slot_available: self.slot_available.clone(),
                    redis_conn: self.redis_conn.lock().await.clone(),
                })
            }
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => {
                // Sender dropped (cancelled)
                self.remove_from_queue(job_id).await;
                self.update_gauges().await;
                Err(AdmissionError::Cancelled)
            }
            Err(_) => {
                // Timeout
                self.remove_from_queue(job_id).await;
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_timeout")
                    .increment(1);
                self.update_gauges().await;
                Err(AdmissionError::QueueTimeout {
                    timeout_ms: queue_timeout_ms,
                })
            }
        }
    }

    /// Try to admit immediately without queueing. Returns None if global limit is full.
    async fn try_admit(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        let config = self.config.lock().await;
        let global_limit = config.global_adhoc_limit;
        let user_limit = config.per_user_limit;
        drop(config);

        // Try Redis first if available
        let redis_conn = self.redis_conn.lock().await.clone();
        if let Some(mut conn) = redis_conn {
            let user_key = redis_user_key(&user_id);

            let result: Result<i64, _> = redis::cmd("EVAL")
                .arg(ACQUIRE_LUA)
                .arg(2) // number of KEYS
                .arg(REDIS_GLOBAL_KEY)
                .arg(&user_key)
                .arg(global_limit)
                .arg(user_limit)
                .arg(REDIS_USER_KEY_TTL_SECS)
                .query_async(&mut conn)
                .await;

            match result {
                Ok(1) => {
                    // Admitted via Redis — also update local counters for gauges
                    self.active_adhoc.fetch_add(1, AtomicOrdering::SeqCst);
                    self.per_user_active
                        .entry(user_id)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);

                    return Ok(Some(AdmissionPermit {
                        user_id,
                        bypassed: false,
                        active_adhoc: self.active_adhoc.clone(),
                        per_user_active: self.per_user_active.clone(),
                        slot_available: self.slot_available.clone(),
                        redis_conn: Some(conn),
                    }));
                }
                Ok(-2) => {
                    // Per-user limit exceeded
                    counter!("nanosiem_search_jobs_rejected_total", "reason" => "user_limit")
                        .increment(1);
                    return Err(AdmissionError::UserLimitExceeded { limit: user_limit });
                }
                Ok(-1) => {
                    // Global limit full — caller should enqueue
                    return Ok(None);
                }
                Ok(v) => {
                    tracing::warn!(
                        "Unexpected Lua script return value: {}, falling back to local",
                        v
                    );
                    // Fall through to local admission
                }
                Err(e) => {
                    tracing::warn!("Redis admission check failed, falling back to local: {}", e);
                    // Fall through to local admission
                }
            }
        }

        // Fallback: local atomics (single-instance or Redis unavailable)
        self.try_admit_local(user_id, global_limit, user_limit)
    }

    /// Local-only admission check (no Redis)
    fn try_admit_local(
        &self,
        user_id: uuid::Uuid,
        global_limit: u32,
        user_limit: u32,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        // Check per-user limit
        let user_count = self
            .per_user_active
            .get(&user_id)
            .map(|r| *r.value())
            .unwrap_or(0);

        if user_count >= user_limit {
            counter!("nanosiem_search_jobs_rejected_total", "reason" => "user_limit").increment(1);
            return Err(AdmissionError::UserLimitExceeded { limit: user_limit });
        }

        // Check global limit
        let current = self.active_adhoc.load(AtomicOrdering::SeqCst);
        if current >= global_limit {
            return Ok(None); // Full — caller should enqueue
        }

        // Atomically increment local counters
        self.active_adhoc.fetch_add(1, AtomicOrdering::SeqCst);
        self.per_user_active
            .entry(user_id)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        Ok(Some(AdmissionPermit {
            user_id,
            bypassed: false,
            active_adhoc: self.active_adhoc.clone(),
            per_user_active: self.per_user_active.clone(),
            slot_available: self.slot_available.clone(),
            redis_conn: None, // No Redis DECR needed for local-only
        }))
    }

    /// Update Prometheus gauges for queue depth and active queries
    async fn update_gauges(&self) {
        let queued = self.queue.lock().await.len() as f64;
        let active = self.active_adhoc.load(AtomicOrdering::SeqCst) as f64;
        gauge!("nanosiem_search_queue_depth").set(queued);
        gauge!("nanosiem_search_active_queries").set(active);
    }

    /// Cancel a queued search by job_id (before it starts executing)
    pub async fn cancel_queued(&self, job_id: &str) {
        self.remove_from_queue(job_id).await;
    }

    /// Get 1-based queue position for a job
    pub async fn queue_position(&self, job_id: &str) -> Option<u32> {
        let queue = self.queue.lock().await;
        // BinaryHeap doesn't support indexed access, so we iterate
        let mut sorted: Vec<&QueuedSearch> = queue.iter().collect();
        sorted.sort_by(|a, b| b.cmp(a)); // Reverse because BinaryHeap is max-heap
        sorted
            .iter()
            .position(|q| q.job_id == job_id)
            .map(|pos| (pos + 1) as u32)
    }

    /// Get total queue depth
    pub async fn queue_depth(&self) -> u32 {
        self.queue.lock().await.len() as u32
    }

    /// Get admission statistics
    pub async fn stats(&self) -> AdmissionStats {
        let active_adhoc = self.active_adhoc.load(AtomicOrdering::SeqCst);
        let queued = self.queue.lock().await.len() as u32;
        let per_user_counts: Vec<(String, u32)> = self
            .per_user_active
            .iter()
            .map(|r| (r.key().to_string(), *r.value()))
            .collect();

        AdmissionStats {
            active_adhoc,
            queued,
            per_user_counts,
        }
    }

    /// Hot-reload configuration without restart
    pub async fn update_config(&self, new_config: AdmissionConfig) {
        let mut config = self.config.lock().await;
        // Skip if nothing changed
        if config.global_adhoc_limit == new_config.global_adhoc_limit
            && config.per_user_limit == new_config.per_user_limit
            && config.max_queue_depth == new_config.max_queue_depth
            && config.queue_timeout_ms == new_config.queue_timeout_ms
        {
            return;
        }
        tracing::info!(
            "Admission config updated: global_adhoc_limit={}->{}, per_user_limit={}->{}, max_queue_depth={}->{}, queue_timeout_ms={}->{}",
            config.global_adhoc_limit, new_config.global_adhoc_limit,
            config.per_user_limit, new_config.per_user_limit,
            config.max_queue_depth, new_config.max_queue_depth,
            config.queue_timeout_ms, new_config.queue_timeout_ms,
        );
        *config = new_config;
        // Wake any waiters so they can re-check limits (new limit might be higher)
        self.slot_available.notify_waiters();
    }

    /// Start the background drain loop that admits queued searches when slots free up
    pub fn start_drain_loop(self: &Arc<Self>) {
        let controller = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                controller.slot_available.notified().await;
                controller.drain_queue().await;
            }
        });
    }

    /// Try to admit queued searches when slots become available
    async fn drain_queue(&self) {
        let config = self.config.lock().await;
        let global_limit = config.global_adhoc_limit;
        let _per_user_limit = config.per_user_limit;
        drop(config);

        let mut queue = self.queue.lock().await;

        // For drain, check current count — use Redis if available, else local
        let current_count = {
            let redis_conn = self.redis_conn.lock().await.clone();
            if let Some(mut conn) = redis_conn {
                let count: Result<u32, _> = redis::cmd("GET")
                    .arg(REDIS_GLOBAL_KEY)
                    .query_async(&mut conn)
                    .await;
                count.unwrap_or_else(|_| self.active_adhoc.load(AtomicOrdering::SeqCst))
            } else {
                self.active_adhoc.load(AtomicOrdering::SeqCst)
            }
        };

        if current_count >= global_limit {
            return; // Still full
        }

        // Collect items to admit
        let mut remaining = BinaryHeap::new();
        while let Some(queued) = queue.pop() {
            let current = self.active_adhoc.load(AtomicOrdering::SeqCst);
            if current >= global_limit {
                remaining.push(queued);
                // Put back remaining items
                while let Some(q) = queue.pop() {
                    remaining.push(q);
                }
                break;
            }

            // Increment local counter (Redis increment happens in acquire's permit creation)
            self.active_adhoc.fetch_add(1, AtomicOrdering::SeqCst);

            // Also increment Redis if available
            let redis_conn = self.redis_conn.lock().await.clone();
            if let Some(mut conn) = redis_conn {
                let _: Result<(), _> = redis::cmd("INCR")
                    .arg(REDIS_GLOBAL_KEY)
                    .query_async(&mut conn)
                    .await;
            }

            let _ = queued.tx.send(Ok(()));
        }

        *queue = remaining;
        // Update gauges after draining
        gauge!("nanosiem_search_queue_depth").set(queue.len() as f64);
        gauge!("nanosiem_search_active_queries")
            .set(self.active_adhoc.load(AtomicOrdering::SeqCst) as f64);
    }

    /// Remove a job from the queue
    async fn remove_from_queue(&self, job_id: &str) {
        let mut queue = self.queue.lock().await;
        let mut remaining = BinaryHeap::new();
        while let Some(queued) = queue.pop() {
            if queued.job_id == job_id {
                let _ = queued.tx.send(Err(AdmissionError::Cancelled));
            } else {
                remaining.push(queued);
            }
        }
        *queue = remaining;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_priority_ordering() {
        assert!(QueryPriority::Detection.ordinal() < QueryPriority::Interactive.ordinal());
        assert!(QueryPriority::Interactive.ordinal() < QueryPriority::Analytics.ordinal());
    }

    #[test]
    fn test_detection_bypasses_queue() {
        assert!(QueryPriority::Detection.bypasses_queue());
        assert!(QueryPriority::NearRealtime.bypasses_queue());
        assert!(!QueryPriority::Interactive.bypasses_queue());
        assert!(!QueryPriority::Analytics.bypasses_queue());
    }

    #[test]
    fn test_ch_settings() {
        let det = QueryPriority::Detection.to_ch_settings();
        assert_eq!(det.max_execution_time, 30);
        assert_eq!(det.priority, 1);

        let interactive = QueryPriority::Interactive.to_ch_settings();
        assert_eq!(interactive.max_execution_time, 300);
        assert_eq!(interactive.priority, 3);

        let analytics = QueryPriority::Analytics.to_ch_settings();
        assert_eq!(analytics.max_execution_time, 3600);
        assert_eq!(analytics.priority, 5);
    }

    /// NAN-709: only Analytics yields before claiming an admit slot. Detection
    /// and NearRealtime bypass admission entirely (so the value would never
    /// be consulted), Interactive is the priority we want to win the race.
    #[test]
    fn admit_delay_only_applies_to_analytics() {
        assert_eq!(QueryPriority::Detection.admit_delay(), None);
        assert_eq!(QueryPriority::NearRealtime.admit_delay(), None);
        assert_eq!(QueryPriority::Interactive.admit_delay(), None);
        assert_eq!(
            QueryPriority::Analytics.admit_delay(),
            Some(std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn test_default_config() {
        let config = AdmissionConfig::default();
        assert_eq!(config.global_adhoc_limit, 30);
        assert_eq!(config.per_user_limit, 5);
        assert_eq!(config.max_queue_depth, 100);
        // NAN-714: bumped to 300_000 (5 min) to match Interactive
        // max_execution_time. See AdmissionConfig::default.
        assert_eq!(config.queue_timeout_ms, 300_000);
    }

    #[tokio::test]
    async fn test_detection_always_admitted() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 0, // no ad-hoc slots
            per_user_limit: 0,
            max_queue_depth: 0,
            queue_timeout_ms: 1,
        });

        let user = Uuid::now_v7();
        let permit = controller
            .acquire("job1", user, QueryPriority::Detection)
            .await;
        assert!(permit.is_ok());
    }

    #[tokio::test]
    async fn test_admit_within_limits() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 5,
            per_user_limit: 3,
            max_queue_depth: 10,
            queue_timeout_ms: 1000,
        });

        let user = Uuid::now_v7();
        let mut permits = Vec::new();

        // Should admit 3 queries for the same user
        for i in 0..3 {
            let permit = controller
                .acquire(&format!("job{}", i), user, QueryPriority::Interactive)
                .await;
            assert!(permit.is_ok(), "Should admit query {}", i);
            permits.push(permit.unwrap());
        }

        // 4th should fail with UserLimitExceeded
        let result = controller
            .acquire("job3", user, QueryPriority::Interactive)
            .await;
        assert!(matches!(
            result,
            Err(AdmissionError::UserLimitExceeded { .. })
        ));

        // Different user should still be admitted
        let user2 = Uuid::now_v7();
        let permit = controller
            .acquire("job4", user2, QueryPriority::Interactive)
            .await;
        assert!(permit.is_ok());
        permits.push(permit.unwrap());

        assert_eq!(controller.stats().await.active_adhoc, 4);
    }

    #[tokio::test]
    async fn test_permit_drop_frees_slot() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            per_user_limit: 5,
            max_queue_depth: 10,
            queue_timeout_ms: 1000,
        });

        let user = Uuid::now_v7();

        {
            let _permit = controller
                .acquire("job1", user, QueryPriority::Interactive)
                .await
                .unwrap();
            assert_eq!(controller.stats().await.active_adhoc, 1);
        }
        // Permit dropped
        assert_eq!(controller.stats().await.active_adhoc, 0);

        // Should be able to acquire again
        let _permit2 = controller
            .acquire("job2", user, QueryPriority::Interactive)
            .await
            .unwrap();
        assert_eq!(controller.stats().await.active_adhoc, 1);
    }

    #[tokio::test]
    async fn test_queue_full() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            per_user_limit: 10,
            max_queue_depth: 0, // no queue
            queue_timeout_ms: 100,
        });

        let user = Uuid::now_v7();
        let _permit = controller
            .acquire("job1", user, QueryPriority::Interactive)
            .await
            .unwrap();

        // Second query should fail with QueueFull since max_queue_depth=0
        let user2 = Uuid::now_v7();
        let result = controller
            .acquire("job2", user2, QueryPriority::Interactive)
            .await;
        assert!(matches!(result, Err(AdmissionError::QueueFull { .. })));
    }

    #[tokio::test]
    async fn test_cancel_queued() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            per_user_limit: 10,
            max_queue_depth: 10,
            queue_timeout_ms: 5000,
        }));

        let user = Uuid::now_v7();
        let _permit = controller
            .acquire("job1", user, QueryPriority::Interactive)
            .await
            .unwrap();

        // Enqueue a second job in a separate task
        let controller2 = Arc::clone(&controller);
        let user2 = Uuid::now_v7();
        let handle = tokio::spawn(async move {
            controller2
                .acquire("job2", user2, QueryPriority::Interactive)
                .await
        });

        // Give the spawn a moment to enqueue
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel the queued job
        controller.cancel_queued("job2").await;

        let result = handle.await.unwrap();
        assert!(matches!(result, Err(AdmissionError::Cancelled)));
    }

    #[tokio::test]
    async fn test_update_config() {
        let controller = AdmissionController::new(AdmissionConfig::default());

        let new_config = AdmissionConfig {
            global_adhoc_limit: 50,
            per_user_limit: 10,
            max_queue_depth: 200,
            queue_timeout_ms: 60_000,
        };

        controller.update_config(new_config.clone()).await;

        let config = controller.config.lock().await;
        assert_eq!(config.global_adhoc_limit, 50);
        assert_eq!(config.per_user_limit, 10);
    }
}
