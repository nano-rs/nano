// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search query admission control
//!
//! Priority-based admission controller using either:
//! - **Redis leases** for cluster-wide limits (active/active deployments)
//! - **A local lease ledger** as fallback (single-instance or Redis unavailable)
//!
//! Detection/NRT queries bypass the queue entirely. Interactive/Analytics queries
//! are subject to global, tenant and per-user concurrency limits; any overflow
//! waits in a bounded priority queue. Every permit is a lease that expires at the
//! priority's execution ceiling plus slack, so a permit whose holder died is
//! reclaimed instead of leaking (NAN-3299).

use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{oneshot, Mutex, Notify};

use super::tenant::SearchTenantScope;

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
                max_memory_usage_bytes: Some(5 * 1024 * 1024 * 1024), // 5 GB
                max_threads: 8,
                priority: 1,
                queue_max_wait_ms: 5000,
            },
            QueryPriority::Interactive => ClickHouseQuerySettings {
                max_execution_time: 300,
                max_memory_usage_bytes: Some(20 * 1024 * 1024 * 1024), // 20 GB
                max_threads: 16,
                priority: 3,
                queue_max_wait_ms: 60000,
            },
            QueryPriority::Analytics => ClickHouseQuerySettings {
                max_execution_time: 3600,
                max_memory_usage_bytes: Some(50 * 1024 * 1024 * 1024), // 50 GB
                max_threads: 32,
                priority: 5,
                queue_max_wait_ms: 120000,
            },
        }
    }

    /// Returns ClickHouse query settings capped to the memory budget advertised
    /// by the deployment. Priority tiers still control timeout, threads, and
    /// their preferred memory budget; the ceiling only prevents a request from
    /// raising `max_memory_usage` above what that ClickHouse pod can provide.
    /// Without a ceiling, the deployment's ClickHouse user profile stays in
    /// control.
    pub fn to_ch_settings_with_memory_ceiling(
        &self,
        memory_ceiling_bytes: Option<u64>,
    ) -> ClickHouseQuerySettings {
        let mut settings = self.to_ch_settings();
        settings.max_memory_usage_bytes = memory_ceiling_bytes.map(|ceiling| {
            settings
                .max_memory_usage_bytes
                .expect("priority memory budgets are always defined")
                .min(ceiling)
        });
        settings
    }
}

/// Deployment-provided ceiling for per-query ClickHouse memory overrides.
pub(crate) const CLICKHOUSE_QUERY_MAX_MEMORY_ENV: &str = "CLICKHOUSE_QUERY_MAX_MEMORY_BYTES";

pub(crate) fn query_memory_ceiling_from_env() -> Option<u64> {
    let raw = match std::env::var(CLICKHOUSE_QUERY_MAX_MEMORY_ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return None,
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!(
                env = CLICKHOUSE_QUERY_MAX_MEMORY_ENV,
                "Ignoring non-Unicode ClickHouse query memory ceiling"
            );
            return None;
        }
    };

    match raw.trim().parse::<u64>() {
        Ok(value) if value > 0 => {
            tracing::info!(
                env = CLICKHOUSE_QUERY_MAX_MEMORY_ENV,
                memory_ceiling_bytes = value,
                "ClickHouse per-query memory overrides will honor deployment ceiling"
            );
            Some(value)
        }
        _ => {
            tracing::warn!(
                env = CLICKHOUSE_QUERY_MAX_MEMORY_ENV,
                value = %raw,
                "Ignoring invalid ClickHouse query memory ceiling; expected a positive byte count"
            );
            None
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
    /// Maximum memory usage in bytes. `None` leaves the deployment's ClickHouse
    /// user profile in control instead of raising its configured limit.
    pub max_memory_usage_bytes: Option<u64>,
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
    /// Maximum concurrent ad-hoc queries for one enterprise-shared tenant.
    /// Dedicated/open-core deployments do not consult this value. The cell
    /// ceiling above remains authoritative across all tenants.
    #[serde(default = "default_shared_tenant_adhoc_limit")]
    pub shared_tenant_adhoc_limit: u32,
    /// Maximum concurrent queries per user. Overflow waits in the queue.
    pub per_user_limit: u32,
    /// Maximum queue depth before rejecting new queries
    pub max_queue_depth: u32,
    /// Queue timeout in milliseconds
    pub queue_timeout_ms: u64,
}

const fn default_shared_tenant_adhoc_limit() -> u32 {
    10
}

/// NAN-3299: one Search page run holds a rows search, a histogram and a
/// field-stats request at once (plus a rerun's overlap while the superseded
/// run is cancelled). Five permits per user failed single searches with 429.
pub const DEFAULT_PER_USER_LIMIT: u32 = 10;

/// NAN-3286: environment override for one enterprise-shared tenant's queued
/// (waiting, not yet admitted) searches in this process.
pub const SHARED_TENANT_QUEUE_LIMIT_ENV: &str = "NANO_SEARCH_SHARED_TENANT_QUEUE_LIMIT";

/// One shared tenant's share of the process queue: the override when set,
/// else `max(10, max_queue_depth / 4)`, never above `max_queue_depth`.
fn shared_tenant_queue_limit(max_queue_depth: u32, override_limit: Option<u32>) -> u32 {
    override_limit
        .unwrap_or_else(|| (max_queue_depth / 4).max(10))
        .min(max_queue_depth)
}

/// Waiters every shared tenant may queue even when other tenants have filled
/// the process queue, so a full queue cannot fail an idle tenant's first
/// searches with `QueueFull`. Bounded per tenant by its own quota.
fn shared_tenant_reserved_queue(tenant_limit: u32) -> u32 {
    (tenant_limit / 5).max(1).min(tenant_limit)
}

/// NAN-3299: waiters one user may queue beyond their running searches. A
/// per-user overflow waits instead of failing, but one user still cannot
/// fill the process (or tenant) queue on their own.
fn per_user_queue_limit(per_user_limit: u32) -> u32 {
    per_user_limit.saturating_mul(2).max(1)
}

/// NAN-3299: slots one user's auxiliary requests (histogram, field stats)
/// may hold. The remainder is reserved for primary (rows) searches so the
/// companions of a run can never starve the rows request of that run.
fn auxiliary_user_limit(per_user_limit: u32) -> u32 {
    if per_user_limit <= 1 {
        return per_user_limit;
    }
    per_user_limit - (per_user_limit / 4).max(1)
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            global_adhoc_limit: 30,
            shared_tenant_adhoc_limit: default_shared_tenant_adhoc_limit(),
            per_user_limit: DEFAULT_PER_USER_LIMIT,
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

/// Which part of one search run a request is (NAN-3299).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionLane {
    /// The rows search itself (and every non-UI caller).
    Primary,
    /// A companion of a rows search: histogram, field statistics. Capped
    /// below the per-user limit and queued behind primary searches of the
    /// same priority.
    Auxiliary,
}

impl AdmissionLane {
    const fn ordinal(self) -> u8 {
        match self {
            AdmissionLane::Primary => 0,
            AdmissionLane::Auxiliary => 1,
        }
    }
}

/// Errors returned by the admission controller
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The user already has `limit` running searches and their share of the
    /// queue is full too. Overflow below that bound waits instead.
    #[error("Per-user query limit exceeded ({limit} concurrent queries)")]
    UserLimitExceeded { limit: u32 },
    #[error("Search queue is full ({depth} queries waiting)")]
    QueueFull { depth: u32 },
    #[error("Search queue timeout after {timeout_ms}ms")]
    QueueTimeout { timeout_ms: u64 },
    #[error("Query cancelled while queued")]
    Cancelled,
    #[error("Enterprise-shared search admission is unavailable")]
    Unavailable,
}

// ============================================================================
// Permit leases
// ============================================================================

/// Slack above a priority's execution ceiling before an unreleased permit is
/// treated as orphaned and reclaimed.
const PERMIT_LEASE_SLACK_SECS: u64 = 60;

/// NAN-3299: every permit is a lease that ends at the priority's ClickHouse
/// execution ceiling plus slack. A permit whose holder died (search pod
/// restart mid-query, a release that never reached Redis, a stuck task) is
/// reclaimed once its lease ends, regardless of how busy the user is.
fn permit_lease(priority: QueryPriority) -> std::time::Duration {
    std::time::Duration::from_secs(
        u64::from(priority.to_ch_settings().max_execution_time) + PERMIT_LEASE_SLACK_SECS,
    )
}

fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

struct LocalLease {
    subject: AdmissionSubject,
    lane: AdmissionLane,
    expires_at: Instant,
}

/// In-process permit ledger: the local admission fallback and the source of
/// the gauges and stats. Each permit is a lease with its own deadline, so a
/// permit that is never dropped is reclaimed when its lease ends instead of
/// holding a slot until the process restarts.
#[derive(Default)]
struct LocalLedger {
    next_id: u64,
    leases: HashMap<u64, LocalLease>,
    per_tenant: HashMap<uuid::Uuid, u32>,
    per_user: HashMap<AdmissionSubject, u32>,
    per_user_auxiliary: HashMap<AdmissionSubject, u32>,
}

fn increment<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u32>, key: K) {
    *map.entry(key).or_insert(0) += 1;
}

fn decrement<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u32>, key: &K) {
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(key);
        }
    }
}

impl LocalLedger {
    fn active(&self) -> u32 {
        self.leases.len() as u32
    }

    fn user_count(&self, subject: &AdmissionSubject) -> u32 {
        self.per_user.get(subject).copied().unwrap_or(0)
    }

    fn user_auxiliary_count(&self, subject: &AdmissionSubject) -> u32 {
        self.per_user_auxiliary.get(subject).copied().unwrap_or(0)
    }

    fn tenant_count(&self, tenant_id: &uuid::Uuid) -> u32 {
        self.per_tenant.get(tenant_id).copied().unwrap_or(0)
    }

    fn insert(
        &mut self,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        expires_at: Instant,
    ) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        self.leases.insert(
            id,
            LocalLease {
                subject,
                lane,
                expires_at,
            },
        );
        if let Some(tenant_id) = subject.tenant_id {
            increment(&mut self.per_tenant, tenant_id);
        }
        increment(&mut self.per_user, subject);
        if lane == AdmissionLane::Auxiliary {
            increment(&mut self.per_user_auxiliary, subject);
        }
        id
    }

    /// Release one lease. False when it was already reclaimed as expired.
    fn release(&mut self, id: u64) -> bool {
        let Some(lease) = self.leases.remove(&id) else {
            return false;
        };
        if let Some(tenant_id) = lease.subject.tenant_id {
            decrement(&mut self.per_tenant, &tenant_id);
        }
        decrement(&mut self.per_user, &lease.subject);
        if lease.lane == AdmissionLane::Auxiliary {
            decrement(&mut self.per_user_auxiliary, &lease.subject);
        }
        true
    }

    /// Reclaim every lease whose deadline has passed. Returns how many.
    fn reclaim_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<(u64, AdmissionSubject)> = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.expires_at <= now)
            .map(|(id, lease)| (*id, lease.subject))
            .collect();
        for (id, subject) in &expired {
            self.release(*id);
            tracing::warn!(
                subject = %subject.metrics_identity(),
                "search admission permit lease expired without release; slot reclaimed"
            );
        }
        if !expired.is_empty() {
            counter!("nanosiem_search_admission_permits_reclaimed_total", "backend" => "local")
                .increment(expired.len() as u64);
        }
        expired.len()
    }
}

fn lock_ledger(ledger: &std::sync::Mutex<LocalLedger>) -> std::sync::MutexGuard<'_, LocalLedger> {
    ledger.lock().unwrap_or_else(|poisoned| {
        tracing::error!("search admission local ledger was poisoned; repairing");
        poisoned.into_inner()
    })
}

// ============================================================================
// Redis lease keys
// ============================================================================

/// NAN-3299: admission state is a sorted set of permit ids scored by lease
/// expiry (Unix ms), not a counter. The `v2` namespace keeps these sets apart
/// from the retired counter strings, which expire on their own TTL; during a
/// rolling deploy old and new replicas therefore count separate budgets.
const REDIS_GLOBAL_KEY: &str = "search:admission:v2:active";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AdmissionSubject {
    tenant_id: Option<uuid::Uuid>,
    user_id: uuid::Uuid,
}

impl AdmissionSubject {
    const fn new(scope: SearchTenantScope, user_id: uuid::Uuid) -> Self {
        Self {
            tenant_id: scope.tenant_id(),
            user_id,
        }
    }

    fn metrics_identity(self) -> String {
        match self.tenant_id {
            Some(tenant_id) => format!("{tenant_id}/{user_id}", user_id = self.user_id),
            None => self.user_id.to_string(),
        }
    }

    fn belongs_to(self, scope: SearchTenantScope) -> bool {
        self.tenant_id == scope.tenant_id()
    }

    const fn scope(self) -> SearchTenantScope {
        match self.tenant_id {
            Some(tenant_id) => SearchTenantScope::EnterpriseShared(tenant_id),
            None => SearchTenantScope::Dedicated,
        }
    }
}

fn redis_user_key(subject: AdmissionSubject) -> String {
    match subject.tenant_id {
        None => format!("search:admission:v2:user:{}", subject.user_id),
        Some(tenant_id) => format!(
            "search:admission:v2:tenant:{tenant_id}:user:{}",
            subject.user_id
        ),
    }
}

fn redis_user_auxiliary_key(subject: AdmissionSubject) -> String {
    format!("{}:aux", redis_user_key(subject))
}

fn redis_tenant_key(tenant_id: uuid::Uuid) -> String {
    format!("search:admission:v2:tenant:{tenant_id}:active")
}

/// Every key one permit is recorded in, in the order `ACQUIRE_LUA` expects:
/// cell, user, user-auxiliary, then the tenant key for shared subjects.
fn redis_permit_keys(subject: AdmissionSubject) -> Vec<String> {
    let mut keys = vec![
        REDIS_GLOBAL_KEY.to_string(),
        redis_user_key(subject),
        redis_user_auxiliary_key(subject),
    ];
    if let Some(tenant_id) = subject.tenant_id {
        keys.push(redis_tenant_key(tenant_id));
    }
    keys
}

/// Idle-key garbage collection only. Correctness comes from each member's
/// expiry score, so refreshing this TTL on every acquire can no longer pin a
/// leaked permit; it must stay above the longest lease (Analytics).
const REDIS_ADMISSION_KEY_TTL_SECS: i64 = 7800;

/// Atomic prune + check + lease for one permit.
///
/// KEYS[1] = cell, KEYS[2] = user, KEYS[3] = user auxiliary,
/// KEYS[4] = tenant (enterprise-shared only)
/// ARGV[1] = now (Unix ms), ARGV[2] = lease expiry (Unix ms), ARGV[3] = permit id,
/// ARGV[4] = cell limit, ARGV[5] = user limit,
/// ARGV[6] = auxiliary user limit, or -1 for a primary request,
/// ARGV[7] = tenant limit (ignored without KEYS[4]), ARGV[8] = key TTL seconds
///
/// Returns 1 admitted, -1 cell full, -2 user full, -3 tenant full. Every
/// "full" answer is queueable; expired leases are pruned before counting.
const ACQUIRE_LUA: &str = r#"
local now = tonumber(ARGV[1])
local expires = tonumber(ARGV[2])
local permit = ARGV[3]
local cell_limit = tonumber(ARGV[4])
local user_limit = tonumber(ARGV[5])
local auxiliary_limit = tonumber(ARGV[6])
local tenant_limit = tonumber(ARGV[7])
local key_ttl = tonumber(ARGV[8])
local has_tenant = #KEYS == 4

for i = 1, #KEYS do
    redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now)
end

if redis.call('ZCARD', KEYS[2]) >= user_limit then
    return -2
end
if auxiliary_limit >= 0 and redis.call('ZCARD', KEYS[3]) >= auxiliary_limit then
    return -2
end
if has_tenant and redis.call('ZCARD', KEYS[4]) >= tenant_limit then
    return -3
end
if redis.call('ZCARD', KEYS[1]) >= cell_limit then
    return -1
end

local function lease(key)
    redis.call('ZADD', key, expires, permit)
    redis.call('EXPIRE', key, key_ttl)
end
lease(KEYS[1])
lease(KEYS[2])
if auxiliary_limit >= 0 then
    lease(KEYS[3])
end
if has_tenant then
    lease(KEYS[4])
end
return 1
"#;

/// Atomically remove one permit from every key it could be recorded in.
/// Removing an absent member is a no-op, so a release after the lease was
/// already pruned cannot erase another permit.
const RELEASE_LUA: &str = r#"
for i = 1, #KEYS do
    redis.call('ZREM', KEYS[i], ARGV[1])
end
return 1
"#;

enum AdmissionAttempt {
    Admitted(AdmissionPermit),
    CellFull,
    TenantFull,
    UserFull,
}

// ============================================================================
// AdmissionPermit
// ============================================================================

struct RedisLease {
    conn: crate::redis_transport::ReconnectingConnection,
    permit_id: String,
}

/// RAII guard — dropping it frees an admission slot and wakes the next queued search.
///
/// The local ledger lease is always released; when Redis admitted the permit,
/// `drop` also spawns a fire-and-forget atomic Redis release. Lease expiry
/// (local and Redis) recovers permits after process loss or a lost release.
pub struct AdmissionPermit {
    subject: AdmissionSubject,
    local_lease: Option<u64>,
    ledger: Arc<std::sync::Mutex<LocalLedger>>,
    slot_available: Arc<Notify>,
    redis: Option<RedisLease>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let Some(lease_id) = self.local_lease.take() else {
            // Detection/NRT bypass permits hold no slot.
            return;
        };

        let active = {
            let mut ledger = lock_ledger(&self.ledger);
            if !ledger.release(lease_id) {
                tracing::warn!(
                    subject = %self.subject.metrics_identity(),
                    "search admission permit released after its lease was reclaimed"
                );
            }
            ledger.active()
        };
        gauge!("nanosiem_search_active_queries").set(active as f64);
        self.slot_available.notify_one();

        // Release the Redis lease as one atomic operation. Permit drop cannot
        // await, so failures are logged and lease expiry is the recovery fence.
        if let Some(RedisLease {
            mut conn,
            permit_id,
        }) = self.redis.take()
        {
            let subject = self.subject;
            tokio::spawn(async move {
                let keys = redis_permit_keys(subject);
                let mut command = redis::cmd("EVAL");
                command
                    .arg(RELEASE_LUA)
                    .arg(keys.len())
                    .arg(&keys)
                    .arg(&permit_id);
                if let Err(error) = command.query_async::<i64>(&mut conn).await {
                    tracing::error!(
                        error = %error,
                        tenant_id = ?subject.tenant_id,
                        "search admission Redis permit release failed; lease expiry recovers it"
                    );
                }
            });
        }
    }
}

/// NAN-3286: whether a new waiter is refused, and at which depth. Dedicated
/// subjects keep the historical single process bound. A shared tenant is
/// refused at its own quota; the process bound applies to it only once it
/// already holds its reserved waiters.
fn queue_rejection(
    subject: AdmissionSubject,
    queued: usize,
    tenant_queued: usize,
    max_queue_depth: u32,
    override_limit: Option<u32>,
) -> Option<u32> {
    if subject.tenant_id.is_none() {
        return (queued >= max_queue_depth as usize).then_some(max_queue_depth);
    }
    let tenant_limit = shared_tenant_queue_limit(max_queue_depth, override_limit);
    if tenant_queued >= tenant_limit as usize {
        return Some(tenant_limit);
    }
    let reserved = shared_tenant_reserved_queue(tenant_limit) as usize;
    (queued >= max_queue_depth as usize && tenant_queued >= reserved).then_some(max_queue_depth)
}

/// A queued search waiting for admission
struct QueuedSearch {
    job_id: String,
    subject: AdmissionSubject,
    require_distributed: bool,
    priority: QueryPriority,
    lane: AdmissionLane,
    /// NAN-3286: fair-share position within this tenant's own waiters
    /// (one past its newest queued waiter's rank, 0 when it has none). The
    /// drain serves equal-priority waiters by rank first, so tenants are
    /// served round-robin instead of one tenant's backlog going first.
    tenant_rank: u64,
    enqueued_at: Instant,
    /// Sender to notify when admitted
    tx: oneshot::Sender<Result<AdmissionPermit, AdmissionError>>,
}

impl PartialEq for QueuedSearch {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
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
        // Higher priority (lower ordinal) first, then primary before
        // auxiliary requests (NAN-3299), then the lower per-tenant
        // fair-share rank (round-robin across tenants), then older first
        // (FIFO within one tenant and priority).
        other
            .priority
            .ordinal()
            .cmp(&self.priority.ordinal())
            .then_with(|| other.lane.ordinal().cmp(&self.lane.ordinal()))
            .then_with(|| other.tenant_rank.cmp(&self.tenant_rank))
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
    /// Per-tenant active query counts for enterprise-shared views.
    #[serde(default)]
    pub per_tenant_counts: Vec<(String, u32)>,
}

/// Priority-based admission controller for search queries.
///
/// When a Redis connection is provided, limits are enforced globally across
/// all instances via atomic Lua scripts over per-permit leases. The local
/// ledger is always maintained as a fallback and for Prometheus gauges.
pub struct AdmissionController {
    config: Mutex<AdmissionConfig>,
    /// Local permit leases. The same short critical section serializes the
    /// local check+lease and release paths.
    ledger: Arc<std::sync::Mutex<LocalLedger>>,
    queue: Mutex<BinaryHeap<QueuedSearch>>,
    /// NAN-3286: `NANO_SEARCH_SHARED_TENANT_QUEUE_LIMIT`, read once.
    shared_tenant_queue_limit_override: Option<u32>,
    /// Test hook: a fixed lease instead of the per-priority one.
    lease_override: Option<std::time::Duration>,
    slot_available: Arc<Notify>,
    // Optional Redis connection for cluster-wide counters
    redis_conn: Mutex<Option<crate::redis_transport::ReconnectingConnection>>,
}

impl AdmissionController {
    /// Create a new admission controller with the given configuration
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config: Mutex::new(config),
            ledger: Arc::new(std::sync::Mutex::new(LocalLedger::default())),
            queue: Mutex::new(BinaryHeap::new()),
            shared_tenant_queue_limit_override: std::env::var(SHARED_TENANT_QUEUE_LIMIT_ENV)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok()),
            lease_override: None,
            slot_available: Arc::new(Notify::new()),
            redis_conn: Mutex::new(None),
        }
    }

    /// Set the Redis connection for cluster-wide admission limits.
    /// When set, limits are enforced globally via Redis atomic counters.
    /// Dedicated/open-core callers fall back to local atomics when unavailable;
    /// enterprise-shared callers fail closed.
    pub async fn set_redis(&self, conn: impl Into<crate::redis_transport::ReconnectingConnection>) {
        *self.redis_conn.lock().await = Some(conn.into());
        tracing::info!("Admission controller: Redis cluster-wide limits enabled");
    }

    /// Readiness uses the same connection as admission, including its outage clock.
    pub async fn backend_ready(&self) -> bool {
        self.redis_conn
            .lock()
            .await
            .as_ref()
            .is_some_and(|conn| conn.ready())
    }

    /// Acquire an admission permit for executing a search query.
    ///
    /// - Detection/NRT: Always admitted immediately (bypasses queue).
    /// - Interactive/Analytics: Subject to per-user and global limits.
    ///   If any limit is full, the query is enqueued with priority ordering.
    pub async fn acquire(
        &self,
        job_id: &str,
        user_id: uuid::Uuid,
        priority: QueryPriority,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.acquire_for_scope(job_id, SearchTenantScope::dedicated(), user_id, priority)
            .await
    }

    /// Acquire against one server-resolved tenant/user identity.
    ///
    /// Dedicated callers retain the historical local fallback. Enterprise-shared
    /// callers are namespaced by the immutable tenant UUID and fail closed when
    /// the distributed admission dependency is not available; otherwise two
    /// replicas could each grant the full cell budget.
    pub async fn acquire_for_scope(
        &self,
        job_id: &str,
        scope: SearchTenantScope,
        user_id: uuid::Uuid,
        priority: QueryPriority,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.acquire_for_scope_in_lane(job_id, scope, user_id, priority, AdmissionLane::Primary)
            .await
    }

    /// [`Self::acquire_for_scope`] for a request in an explicit lane. Search
    /// companions (histogram, field stats) use [`AdmissionLane::Auxiliary`].
    pub async fn acquire_for_scope_in_lane(
        &self,
        job_id: &str,
        scope: SearchTenantScope,
        user_id: uuid::Uuid,
        priority: QueryPriority,
        lane: AdmissionLane,
    ) -> Result<AdmissionPermit, AdmissionError> {
        #[cfg(feature = "enterprise")]
        let shared_scope = scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(scope, SearchTenantScope::Dedicated);
        self.acquire_subject_in_lane(
            job_id,
            AdmissionSubject::new(scope, user_id),
            shared_scope,
            priority,
            lane,
        )
        .await
    }

    #[cfg(test)]
    async fn acquire_subject(
        &self,
        job_id: &str,
        subject: AdmissionSubject,
        require_distributed: bool,
        priority: QueryPriority,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.acquire_subject_in_lane(
            job_id,
            subject,
            require_distributed,
            priority,
            AdmissionLane::Primary,
        )
        .await
    }

    fn lease_for(&self, priority: QueryPriority) -> std::time::Duration {
        self.lease_override
            .unwrap_or_else(|| permit_lease(priority))
    }

    async fn acquire_subject_in_lane(
        &self,
        job_id: &str,
        subject: AdmissionSubject,
        require_distributed: bool,
        priority: QueryPriority,
        lane: AdmissionLane,
    ) -> Result<AdmissionPermit, AdmissionError> {
        // Detection/NRT always bypass
        if priority.bypasses_queue() {
            counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                .increment(1);
            return Ok(AdmissionPermit {
                subject,
                local_lease: None,
                ledger: self.ledger.clone(),
                slot_available: self.slot_available.clone(),
                redis: None,
            });
        }

        // Try immediate admission
        match self
            .try_admit(subject, require_distributed, priority, lane)
            .await?
        {
            AdmissionAttempt::Admitted(permit) => {
                counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                    .increment(1);
                self.update_gauges().await;
                return Ok(permit);
            }
            AdmissionAttempt::CellFull
            | AdmissionAttempt::TenantFull
            | AdmissionAttempt::UserFull => {}
        }

        // Enqueue and wait. NAN-3299: a per-user overflow waits here like a
        // cell/tenant overflow; it is refused only when the user's own share
        // of the queue is full as well.
        let (tx, rx) = oneshot::channel();
        let config = self.config.lock().await;
        let queue_timeout_ms = config.queue_timeout_ms;
        let max_queue_depth = config.max_queue_depth;
        let per_user_limit = config.per_user_limit;
        drop(config);

        let enqueued_at = Instant::now();
        {
            let mut queue = self.queue.lock().await;
            let user_queued = queue
                .iter()
                .filter(|queued| queued.subject == subject)
                .count();
            if user_queued >= per_user_queue_limit(per_user_limit) as usize {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "user_limit")
                    .increment(1);
                return Err(AdmissionError::UserLimitExceeded {
                    limit: per_user_limit,
                });
            }
            // NAN-3286: one tenant's waiters are bounded by its own share, so
            // a tenant saturating the process queue cannot turn another
            // tenant's searches into immediate `QueueFull`.
            let same_tenant = || {
                queue
                    .iter()
                    .filter(|queued| queued.subject.tenant_id == subject.tenant_id)
            };
            let tenant_queued = same_tenant().count();
            let tenant_rank = same_tenant()
                .map(|queued| queued.tenant_rank + 1)
                .max()
                .unwrap_or(0);
            if let Some(rejected_at) = queue_rejection(
                subject,
                queue.len(),
                tenant_queued,
                max_queue_depth,
                self.shared_tenant_queue_limit_override,
            ) {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_full")
                    .increment(1);
                return Err(AdmissionError::QueueFull { depth: rejected_at });
            }
            queue.push(QueuedSearch {
                job_id: job_id.to_string(),
                subject,
                require_distributed,
                priority,
                lane,
                tenant_rank,
                enqueued_at,
                tx,
            });
            counter!("nanosiem_search_jobs_queued_total").increment(1);
            gauge!("nanosiem_search_queue_depth").set(queue.len() as f64);
        }
        // Close the check-then-enqueue race with a concurrently dropped
        // permit: even if its notification arrived before this queue insert,
        // the drain loop gets another chance to observe the waiter.
        self.slot_available.notify_one();

        // Wait for slot with timeout
        match tokio::time::timeout(std::time::Duration::from_millis(queue_timeout_ms), rx).await {
            Ok(Ok(Ok(permit))) => {
                // We were admitted by drain_queue and receive the exact permit
                // whose local/distributed leases it took.
                let wait_secs = enqueued_at.elapsed().as_secs_f64();
                histogram!("nanosiem_search_queue_wait_seconds").record(wait_secs);
                counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                    .increment(1);
                self.update_gauges().await;
                Ok(permit)
            }
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => {
                // Sender dropped (cancelled)
                self.remove_from_queue(job_id, Some(subject.scope())).await;
                self.update_gauges().await;
                Err(AdmissionError::Cancelled)
            }
            Err(_) => {
                // Timeout
                self.remove_from_queue(job_id, Some(subject.scope())).await;
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_timeout")
                    .increment(1);
                self.update_gauges().await;
                Err(AdmissionError::QueueTimeout {
                    timeout_ms: queue_timeout_ms,
                })
            }
        }
    }

    fn admitted_permit(
        &self,
        ledger: &mut LocalLedger,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        lease: std::time::Duration,
        redis: Option<RedisLease>,
    ) -> AdmissionPermit {
        let lease_id = ledger.insert(subject, lane, Instant::now() + lease);
        AdmissionPermit {
            subject,
            local_lease: Some(lease_id),
            ledger: self.ledger.clone(),
            slot_available: self.slot_available.clone(),
            redis,
        }
    }

    /// Try to admit immediately without queueing.
    async fn try_admit(
        &self,
        subject: AdmissionSubject,
        require_distributed: bool,
        priority: QueryPriority,
        lane: AdmissionLane,
    ) -> Result<AdmissionAttempt, AdmissionError> {
        let config = self.config.lock().await;
        let global_limit = config.global_adhoc_limit;
        let tenant_limit = config.shared_tenant_adhoc_limit.min(global_limit);
        let user_limit = config.per_user_limit;
        drop(config);
        if subject.tenant_id.is_some() && tenant_limit == 0 {
            tracing::error!(
                tenant_id = ?subject.tenant_id,
                "enterprise-shared tenant admission limit is invalid"
            );
            return Err(AdmissionError::Unavailable);
        }
        let lease = self.lease_for(priority);
        let auxiliary_limit = match lane {
            AdmissionLane::Primary => None,
            AdmissionLane::Auxiliary => Some(auxiliary_user_limit(user_limit)),
        };

        // Try Redis first if available
        let redis_conn = self.redis_conn.lock().await.clone();
        if let Some(mut conn) = redis_conn {
            let keys = redis_permit_keys(subject);
            let permit_id = uuid::Uuid::now_v7().to_string();
            let now_ms = unix_millis_now();
            let expires_ms = now_ms.saturating_add(lease.as_millis() as i64);
            let mut command = redis::cmd("EVAL");
            command
                .arg(ACQUIRE_LUA)
                .arg(keys.len())
                .arg(&keys)
                .arg(now_ms)
                .arg(expires_ms)
                .arg(&permit_id)
                .arg(global_limit)
                .arg(user_limit)
                .arg(auxiliary_limit.map_or(-1, i64::from))
                .arg(tenant_limit)
                .arg(REDIS_ADMISSION_KEY_TTL_SECS);
            let result: Result<i64, _> = command.query_async(&mut conn).await;

            match result {
                Ok(1) => {
                    // Admitted via Redis — also lease locally for gauges.
                    let mut ledger = lock_ledger(&self.ledger);
                    ledger.reclaim_expired(Instant::now());
                    let permit = self.admitted_permit(
                        &mut ledger,
                        subject,
                        lane,
                        lease,
                        Some(RedisLease { conn, permit_id }),
                    );
                    return Ok(AdmissionAttempt::Admitted(permit));
                }
                Ok(-2) => return Ok(AdmissionAttempt::UserFull),
                Ok(-1) => return Ok(AdmissionAttempt::CellFull),
                Ok(-3) if subject.tenant_id.is_some() => {
                    // This tenant is full, but another tenant may still use a
                    // free cell slot. The queue drain skips this tenant until
                    // one of its permits releases.
                    return Ok(AdmissionAttempt::TenantFull);
                }
                Ok(v) => {
                    if require_distributed {
                        tracing::error!(
                            value = v,
                            tenant_id = ?subject.tenant_id,
                            "enterprise-shared Redis admission returned an invalid response"
                        );
                        return Err(AdmissionError::Unavailable);
                    }
                    tracing::warn!(
                        "Unexpected Lua script return value: {}, falling back to local",
                        v
                    );
                    // Fall through to local admission
                }
                Err(e) => {
                    if require_distributed {
                        tracing::error!(
                            error = %e,
                            tenant_id = ?subject.tenant_id,
                            "enterprise-shared Redis admission failed closed"
                        );
                        return Err(AdmissionError::Unavailable);
                    }
                    tracing::warn!("Redis admission check failed, falling back to local: {}", e);
                    // Fall through to local admission
                }
            }
        }

        if require_distributed {
            tracing::error!(
                tenant_id = ?subject.tenant_id,
                "enterprise-shared Redis admission is not configured"
            );
            return Err(AdmissionError::Unavailable);
        }

        // Fallback: local ledger (single-instance or Redis unavailable)
        Ok(self.try_admit_local(
            subject,
            lane,
            lease,
            global_limit,
            tenant_limit,
            user_limit,
            auxiliary_limit,
        ))
    }

    /// Local-only admission check (no Redis)
    #[allow(clippy::too_many_arguments)]
    fn try_admit_local(
        &self,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        lease: std::time::Duration,
        global_limit: u32,
        tenant_limit: u32,
        user_limit: u32,
        auxiliary_limit: Option<u32>,
    ) -> AdmissionAttempt {
        let mut ledger = lock_ledger(&self.ledger);
        ledger.reclaim_expired(Instant::now());

        if ledger.user_count(&subject) >= user_limit {
            return AdmissionAttempt::UserFull;
        }
        if auxiliary_limit.is_some_and(|limit| ledger.user_auxiliary_count(&subject) >= limit) {
            return AdmissionAttempt::UserFull;
        }
        if let Some(tenant_id) = subject.tenant_id {
            if ledger.tenant_count(&tenant_id) >= tenant_limit {
                return AdmissionAttempt::TenantFull;
            }
        }
        if ledger.active() >= global_limit {
            return AdmissionAttempt::CellFull;
        }

        AdmissionAttempt::Admitted(self.admitted_permit(&mut ledger, subject, lane, lease, None))
    }

    fn local_active(&self) -> u32 {
        lock_ledger(&self.ledger).active()
    }

    /// Update Prometheus gauges for queue depth and active queries
    async fn update_gauges(&self) {
        let queued = self.queue.lock().await.len() as f64;
        let active = self.local_active() as f64;
        gauge!("nanosiem_search_queue_depth").set(queued);
        gauge!("nanosiem_search_active_queries").set(active);
    }

    /// Cancel a queued search by job_id (before it starts executing)
    pub async fn cancel_queued(&self, job_id: &str) {
        self.cancel_queued_for_scope(job_id, SearchTenantScope::dedicated())
            .await;
    }

    pub async fn cancel_queued_for_scope(&self, job_id: &str, scope: SearchTenantScope) {
        self.remove_from_queue(job_id, Some(scope)).await;
    }

    /// Get 1-based queue position for a job
    pub async fn queue_position(&self, job_id: &str) -> Option<u32> {
        self.queue_position_for_scope(job_id, SearchTenantScope::dedicated())
            .await
    }

    /// Tenant-relative queue position. A shared caller neither observes nor
    /// mutates another tenant's waiter even if opaque job IDs collide.
    pub async fn queue_position_for_scope(
        &self,
        job_id: &str,
        scope: SearchTenantScope,
    ) -> Option<u32> {
        let queue = self.queue.lock().await;
        // BinaryHeap doesn't support indexed access, so we iterate
        let mut sorted: Vec<&QueuedSearch> = queue
            .iter()
            .filter(|queued| queued.subject.belongs_to(scope))
            .collect();
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
        let queued = self.queue.lock().await.len() as u32;
        let ledger = lock_ledger(&self.ledger);
        AdmissionStats {
            active_adhoc: ledger.active(),
            queued,
            per_user_counts: ledger
                .per_user
                .iter()
                .map(|(subject, count)| (subject.metrics_identity(), *count))
                .collect(),
            per_tenant_counts: ledger
                .per_tenant
                .iter()
                .map(|(tenant_id, count)| (tenant_id.to_string(), *count))
                .collect(),
        }
    }

    /// Hot-reload configuration without restart
    pub async fn update_config(&self, new_config: AdmissionConfig) {
        let mut config = self.config.lock().await;
        // Skip if nothing changed
        if config.global_adhoc_limit == new_config.global_adhoc_limit
            && config.shared_tenant_adhoc_limit == new_config.shared_tenant_adhoc_limit
            && config.per_user_limit == new_config.per_user_limit
            && config.max_queue_depth == new_config.max_queue_depth
            && config.queue_timeout_ms == new_config.queue_timeout_ms
        {
            return;
        }
        tracing::info!(
            "Admission config updated: global_adhoc_limit={}->{}, shared_tenant_adhoc_limit={}->{}, per_user_limit={}->{}, max_queue_depth={}->{}, queue_timeout_ms={}->{}",
            config.global_adhoc_limit, new_config.global_adhoc_limit,
            config.shared_tenant_adhoc_limit, new_config.shared_tenant_adhoc_limit,
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
            // Permit release notifications are process-local, while Redis
            // leases are cluster-wide: another replica's release (including a
            // user's own permit, NAN-3299) and a lease expiring without any
            // release send this process no Notify. Recheck a non-empty queue
            // on a bounded cadence.
            let mut periodic_recheck = tokio::time::interval(std::time::Duration::from_secs(1));
            periodic_recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            periodic_recheck.tick().await;
            loop {
                tokio::select! {
                    _ = controller.slot_available.notified() => {}
                    _ = periodic_recheck.tick() => {
                        if controller.queue.lock().await.is_empty() {
                            continue;
                        }
                    }
                }
                controller.drain_queue().await;
            }
        });
    }

    /// Try to admit queued searches when slots become available
    async fn drain_queue(&self) {
        // Try each request present at the start at most once. Tenant- and
        // user-full work is rotated behind other waiters; a cell-full result
        // stops the pass because no queued request can safely admit then.
        let attempts = self.queue.lock().await.len();
        let mut blocked = Vec::new();
        for _ in 0..attempts {
            // Never hold the queue lock while awaiting Redis. Apart from
            // keeping cancellation responsive, this lets a dropping permit
            // wake another drain without deadlocking behind an I/O attempt.
            let Some(queued) = self.queue.lock().await.pop() else {
                break;
            };

            match self
                .try_admit(
                    queued.subject,
                    queued.require_distributed,
                    queued.priority,
                    queued.lane,
                )
                .await
            {
                Ok(AdmissionAttempt::Admitted(permit)) => {
                    // A timed-out/cancelled receiver may already be gone. Drop
                    // the permit immediately in that case so no lease leaks
                    // and continue looking for a live waiter.
                    let _ = queued.tx.send(Ok(permit));
                }
                Ok(AdmissionAttempt::CellFull) => {
                    // The process/cell ceiling is still full. Preserve the
                    // current and blocked searches' identities.
                    self.queue.lock().await.push(queued);
                    break;
                }
                Ok(AdmissionAttempt::TenantFull | AdmissionAttempt::UserFull) => {
                    // Do not let a saturated tenant or user at the head of the
                    // priority heap block other waiters from a free slot.
                    blocked.push(queued);
                }
                Err(error) => {
                    // A shared admission outage is terminal for this waiter,
                    // but must not stall unrelated tenant/user work behind it.
                    let _ = queued.tx.send(Err(error));
                }
            }
        }

        if !blocked.is_empty() {
            let mut queue = self.queue.lock().await;
            queue.extend(blocked);
        }

        let depth = self.queue.lock().await.len();
        // Update gauges after draining
        gauge!("nanosiem_search_queue_depth").set(depth as f64);
        gauge!("nanosiem_search_active_queries").set(self.local_active() as f64);
    }

    /// Remove a job from the queue
    async fn remove_from_queue(&self, job_id: &str, scope: Option<SearchTenantScope>) {
        let mut queue = self.queue.lock().await;
        let mut remaining = BinaryHeap::new();
        while let Some(queued) = queue.pop() {
            let scope_matches = scope
                .map(|scope| queued.subject.belongs_to(scope))
                .unwrap_or(true);
            if queued.job_id == job_id && scope_matches {
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

    #[test]
    fn deployment_memory_ceiling_only_clamps_memory() {
        let ceiling = 3 * 1024 * 1024 * 1024;
        let analytics = QueryPriority::Analytics.to_ch_settings_with_memory_ceiling(Some(ceiling));

        assert_eq!(analytics.max_memory_usage_bytes, Some(ceiling));
        assert_eq!(analytics.max_execution_time, 3600);
        assert_eq!(analytics.max_threads, 32);
        assert_eq!(analytics.priority, 5);
        assert_eq!(analytics.queue_max_wait_ms, 120_000);
    }

    #[test]
    fn deployment_memory_ceiling_never_raises_priority_budget() {
        let generous_ceiling = 100 * 1024 * 1024 * 1024;
        let detection =
            QueryPriority::Detection.to_ch_settings_with_memory_ceiling(Some(generous_ceiling));
        let legacy = QueryPriority::Detection.to_ch_settings();

        assert_eq!(
            detection.max_memory_usage_bytes,
            legacy.max_memory_usage_bytes
        );
        assert_eq!(
            QueryPriority::Interactive
                .to_ch_settings_with_memory_ceiling(None)
                .max_memory_usage_bytes,
            None
        );
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
        assert_eq!(config.shared_tenant_adhoc_limit, 10);
        assert_eq!(config.per_user_limit, 10);
        assert_eq!(config.max_queue_depth, 100);
        // NAN-714: bumped to 300_000 (5 min) to match Interactive
        // max_execution_time. See AdmissionConfig::default.
        assert_eq!(config.queue_timeout_ms, 300_000);
    }

    #[tokio::test]
    async fn test_detection_always_admitted() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 0, // no ad-hoc slots
            shared_tenant_adhoc_limit: 0,
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
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 5,
            shared_tenant_adhoc_limit: 5,
            per_user_limit: 3,
            max_queue_depth: 10,
            queue_timeout_ms: 5_000,
        }));
        controller.start_drain_loop();

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

        // NAN-3299: the 4th waits in the queue instead of failing.
        let queued_controller = Arc::clone(&controller);
        let fourth = tokio::spawn(async move {
            queued_controller
                .acquire("job3", user, QueryPriority::Interactive)
                .await
        });
        wait_for_depth(&controller, 1).await;

        // Different user should still be admitted
        let user2 = Uuid::now_v7();
        let permit = controller
            .acquire("job4", user2, QueryPriority::Interactive)
            .await;
        assert!(permit.is_ok());
        permits.push(permit.unwrap());
        assert_eq!(controller.stats().await.active_adhoc, 4);
        assert!(!fourth.is_finished(), "per-user overflow waits for a slot");

        // Releasing one of the user's permits admits the waiter.
        permits.remove(0);
        let fourth = tokio::time::timeout(std::time::Duration::from_secs(5), fourth)
            .await
            .expect("queued per-user overflow admits after a release")
            .expect("join")
            .expect("admitted");
        assert_eq!(controller.stats().await.active_adhoc, 4);
        drop(fourth);
    }

    #[tokio::test]
    async fn test_permit_drop_frees_slot() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            shared_tenant_adhoc_limit: 1,
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
            shared_tenant_adhoc_limit: 1,
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
            shared_tenant_adhoc_limit: 1,
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
            shared_tenant_adhoc_limit: 20,
            per_user_limit: 10,
            max_queue_depth: 200,
            queue_timeout_ms: 60_000,
        };

        controller.update_config(new_config.clone()).await;

        let config = controller.config.lock().await;
        assert_eq!(config.global_adhoc_limit, 50);
        assert_eq!(config.shared_tenant_adhoc_limit, 20);
        assert_eq!(config.per_user_limit, 10);
    }

    #[tokio::test]
    async fn shared_default_limits_admit_rows_and_companion_together() {
        let controller = AdmissionController::new(AdmissionConfig::default());
        let subject = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x100),
        );
        let rows = controller
            .acquire_subject("rows", subject, false, QueryPriority::Interactive)
            .await
            .unwrap();
        let companion = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            controller.acquire_subject("companion", subject, false, QueryPriority::Analytics),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(controller.stats().await.active_adhoc, 2);
        drop((rows, companion));
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_missing_distributed_admission_fails_closed() {
        let controller = AdmissionController::new(AdmissionConfig::default());
        let result = controller
            .acquire_for_scope(
                "shared-no-redis",
                SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
                Uuid::from_u128(0x100),
                QueryPriority::Interactive,
            )
            .await;

        assert!(matches!(result, Err(AdmissionError::Unavailable)));
        assert_eq!(controller.stats().await.active_adhoc, 0);
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_tenant_a_queues_at_cap_while_tenant_b_admits() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 3,
            shared_tenant_adhoc_limit: 1,
            per_user_limit: 1,
            max_queue_depth: 3,
            queue_timeout_ms: 1_000,
        }));
        controller.start_drain_loop();
        let tenant_a_user_one = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x100),
        );
        let tenant_a_user_two = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x200),
        );
        let tenant_b_same_raw_user = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb)),
            Uuid::from_u128(0x100),
        );

        let permit_a = controller
            .acquire_subject(
                "tenant-a-user-one",
                tenant_a_user_one,
                false,
                QueryPriority::Interactive,
            )
            .await
            .expect("tenant A's first query should admit");

        let queued_controller = Arc::clone(&controller);
        let queued_a = tokio::spawn(async move {
            queued_controller
                .acquire_subject(
                    "tenant-a-user-two",
                    tenant_a_user_two,
                    false,
                    QueryPriority::Interactive,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if controller.queue_depth().await == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tenant A's second user should queue at the tenant cap");

        let permit_b = controller
            .acquire_subject(
                "tenant-b-same-user",
                tenant_b_same_raw_user,
                false,
                QueryPriority::Interactive,
            )
            .await
            .expect("tenant B must admit while tenant A is at its own cap");
        let stats = controller.stats().await;
        assert_eq!(stats.active_adhoc, 2);
        assert_eq!(stats.per_tenant_counts.len(), 2);
        assert!(stats
            .per_tenant_counts
            .iter()
            .all(|(_, active)| *active == 1));

        drop(permit_a);
        let queued_a_permit = queued_a
            .await
            .expect("tenant A queue task should join")
            .expect("tenant A's queued query should admit after its slot releases");
        drop((queued_a_permit, permit_b));
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_same_tenant_user_cannot_race_past_cap() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 64,
            shared_tenant_adhoc_limit: 64,
            per_user_limit: 2,
            max_queue_depth: 64,
            queue_timeout_ms: 200,
        }));
        let subject = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x100),
        );
        let barrier = Arc::new(tokio::sync::Barrier::new(32));
        let mut tasks = Vec::new();
        for index in 0..32 {
            let controller = Arc::clone(&controller);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                controller
                    .acquire_subject(
                        &format!("shared-race-{index}"),
                        subject,
                        false,
                        QueryPriority::Interactive,
                    )
                    .await
            }));
        }

        let mut permits = Vec::new();
        let mut rejected = 0;
        let mut timed_out = 0;
        for task in tasks {
            match task.await.expect("admission task should join") {
                Ok(permit) => permits.push(permit),
                Err(AdmissionError::UserLimitExceeded { limit: 2 }) => rejected += 1,
                Err(AdmissionError::QueueTimeout { .. }) => timed_out += 1,
                Err(other) => panic!("unexpected admission result: {other}"),
            }
        }
        // Two run; the user's queue share (2x the limit) waits and, with
        // no release, times out; only the overflow beyond that is refused.
        assert_eq!(permits.len(), 2);
        assert_eq!(timed_out, 4);
        assert_eq!(rejected, 26);
        assert_eq!(controller.stats().await.active_adhoc, 2);
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_sync_and_sse_share_one_user_budget() {
        let controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 4,
            shared_tenant_adhoc_limit: 4,
            per_user_limit: 1,
            max_queue_depth: 4,
            queue_timeout_ms: 100,
        });
        let subject = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x100),
        );

        let sync_permit = controller
            .acquire_subject("sync", subject, false, QueryPriority::Interactive)
            .await
            .expect("sync should acquire the shared user slot");
        let sse = controller
            .acquire_subject("sse", subject, false, QueryPriority::Interactive)
            .await;
        // The SSE search waits on the same per-user slot (here until the
        // short queue timeout, since nothing releases it).
        assert!(matches!(sse, Err(AdmissionError::QueueTimeout { .. })));

        drop(sync_permit);
        let sse_after_sync = controller
            .acquire_subject("sse-after-sync", subject, false, QueryPriority::Interactive)
            .await;
        assert!(sse_after_sync.is_ok());
    }

    #[test]
    fn sync_and_sse_service_paths_are_wired_to_the_common_admission_helper() {
        let sync_source = include_str!("service/core_search.rs");
        let sse_source = include_str!("service/streaming.rs");
        let region = |source: &str, name: &str| -> String {
            let marker = format!("pub async fn {name}(");
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("service method {name} not found"));
            let rest = &source[start + marker.len()..];
            let end = rest.find("pub async fn ").unwrap_or(rest.len());
            rest[..end].to_string()
        };

        for (source, method) in [
            (sync_source, "search_with_admission"),
            (sse_source, "search_streaming_with_admission"),
        ] {
            let method = region(source, method);
            assert!(method.contains("required_admission_controller()"));
            assert!(method.contains("acquire_search_admission"));
        }
    }

    fn shared_subject(tenant: u128, user: u128) -> AdmissionSubject {
        AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(tenant)),
            Uuid::from_u128(user),
        )
    }

    async fn wait_for_depth(controller: &AdmissionController, depth: u32) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while controller.queue_depth().await != depth {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("queue never reached depth {depth}"));
    }

    #[test]
    fn shared_tenant_queue_quota_defaults_and_override() {
        assert_eq!(shared_tenant_queue_limit(100, None), 25);
        assert_eq!(shared_tenant_queue_limit(20, None), 10);
        assert_eq!(shared_tenant_queue_limit(3, None), 3);
        assert_eq!(shared_tenant_queue_limit(100, Some(7)), 7);
        assert_eq!(shared_tenant_queue_limit(100, Some(500)), 100);
        assert_eq!(shared_tenant_queue_limit(0, None), 0);
        let dedicated = AdmissionSubject::new(SearchTenantScope::Dedicated, Uuid::from_u128(1));
        assert_eq!(queue_rejection(dedicated, 99, 99, 100, None), None);
        assert_eq!(queue_rejection(dedicated, 100, 100, 100, None), Some(100));
        let shared = shared_subject(0xa, 1);
        assert_eq!(queue_rejection(shared, 24, 24, 100, None), None);
        assert_eq!(queue_rejection(shared, 25, 25, 100, None), Some(25));
        // A full process queue still admits a tenant's reserved waiters.
        assert_eq!(queue_rejection(shared, 100, 0, 100, None), None);
        assert_eq!(queue_rejection(shared, 104, 4, 100, None), None);
        assert_eq!(queue_rejection(shared, 105, 5, 100, None), Some(100));
        assert_eq!(queue_rejection(shared, 0, 0, 0, None), Some(0));
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3286: tenant A saturating the shared queue can neither make tenant
    /// B fail `QueueFull` nor keep B waiting behind A's whole backlog.
    #[tokio::test]
    async fn enterprise_shared_tenant_cannot_starve_another_tenants_queue() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            shared_tenant_adhoc_limit: 1,
            per_user_limit: 1,
            max_queue_depth: 100,
            queue_timeout_ms: 10_000,
        }));
        controller.start_drain_loop();
        let holder = controller
            .acquire_subject(
                "a-holder",
                shared_subject(0xa, 0),
                false,
                QueryPriority::Interactive,
            )
            .await
            .expect("tenant A occupies the one cell slot");

        // Tenant A floods the queue from 100 principals: only its quota waits.
        let mut a_waiters = Vec::new();
        let mut a_rejected = 0;
        for user in 1..=100u128 {
            let flooding = Arc::clone(&controller);
            let handle = tokio::spawn(async move {
                flooding
                    .acquire_subject(
                        &format!("a-{user}"),
                        shared_subject(0xa, user),
                        false,
                        QueryPriority::Interactive,
                    )
                    .await
            });
            if user <= 25 {
                a_waiters.push(handle);
                wait_for_depth(&controller, user as u32).await;
            } else {
                match handle.await.expect("join") {
                    Err(AdmissionError::QueueFull { depth }) => {
                        assert_eq!(depth, 25);
                        a_rejected += 1;
                    }
                    other => panic!("tenant A past its quota must be refused: {:?}", other.err()),
                }
            }
        }
        assert_eq!(a_rejected, 75);
        assert_eq!(controller.queue_depth().await, 25);

        // Tenant B is queued, not refused.
        let b_controller = Arc::clone(&controller);
        let b = tokio::spawn(async move {
            b_controller
                .acquire_subject(
                    "b-1",
                    shared_subject(0xb, 1),
                    false,
                    QueryPriority::Interactive,
                )
                .await
        });
        wait_for_depth(&controller, 26).await;

        // Fair drain: B is served after at most one of A's 25 older waiters.
        drop(holder);
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if b.is_finished() {
                    return None;
                }
                for (index, waiter) in a_waiters.iter().enumerate() {
                    if waiter.is_finished() {
                        return Some(index);
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a waiter is admitted when the slot frees");
        if let Some(index) = first {
            let permit = a_waiters
                .remove(index)
                .await
                .expect("join")
                .expect("A admitted");
            drop(permit);
        }
        let b_permit = tokio::time::timeout(std::time::Duration::from_secs(5), b)
            .await
            .expect("tenant B must be admitted ahead of A's backlog")
            .expect("join")
            .expect("tenant B admitted");
        assert_eq!(
            controller.queue_depth().await,
            24,
            "B jumped A's remaining backlog"
        );
        drop(b_permit);
        for waiter in a_waiters {
            waiter.abort();
        }
    }

    /// NAN-3286: several tenants filling the whole process queue still leave
    /// an idle tenant its reserved waiters.
    #[tokio::test]
    async fn full_shared_queue_still_admits_an_idle_tenants_reserved_waiter() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            shared_tenant_adhoc_limit: 1,
            per_user_limit: 1,
            max_queue_depth: 20,
            queue_timeout_ms: 10_000,
        }));
        let _holder = controller
            .acquire_subject(
                "holder",
                shared_subject(0xf, 0),
                false,
                QueryPriority::Interactive,
            )
            .await
            .expect("slot holder");
        let mut waiters = Vec::new();
        for (tenant, count) in [(0xa, 10u128), (0xc, 10)] {
            for user in 0..count {
                let controller = Arc::clone(&controller);
                waiters.push(tokio::spawn(async move {
                    controller
                        .acquire_subject(
                            &format!("{tenant}-{user}"),
                            shared_subject(tenant, user),
                            false,
                            QueryPriority::Interactive,
                        )
                        .await
                }));
            }
        }
        wait_for_depth(&controller, 20).await;
        let b_controller = Arc::clone(&controller);
        let b = tokio::spawn(async move {
            b_controller
                .acquire_subject(
                    "b",
                    shared_subject(0xb, 1),
                    false,
                    QueryPriority::Interactive,
                )
                .await
        });
        wait_for_depth(&controller, 21).await;
        assert!(
            !b.is_finished(),
            "tenant B waits instead of failing QueueFull"
        );
        b.abort();
        for waiter in waiters {
            waiter.abort();
        }
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_tenants_still_share_the_cell_ceiling_and_queue() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 1,
            shared_tenant_adhoc_limit: 1,
            per_user_limit: 1,
            max_queue_depth: 2,
            queue_timeout_ms: 1_000,
        }));
        controller.start_drain_loop();
        let tenant_a = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            Uuid::from_u128(0x100),
        );
        let tenant_b = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb)),
            Uuid::from_u128(0x200),
        );
        let permit_a = controller
            .acquire_subject("tenant-a", tenant_a, false, QueryPriority::Interactive)
            .await
            .expect("tenant A should occupy the one cell slot");

        let queued_controller = Arc::clone(&controller);
        let queued = tokio::spawn(async move {
            queued_controller
                .acquire_subject("tenant-b", tenant_b, false, QueryPriority::Interactive)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if controller.queue_depth().await == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tenant B should enter the bounded cell queue");

        drop(permit_a);
        let permit_b = queued
            .await
            .expect("queued task should join")
            .expect("tenant B should admit when the cell slot is released");
        assert_eq!(controller.stats().await.active_adhoc, 1);
        drop(permit_b);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_redis_user_keys_include_tenant_and_user() {
        let user = Uuid::from_u128(0x100);
        let a = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa)),
            user,
        );
        let b = AdmissionSubject::new(
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb)),
            user,
        );
        assert_ne!(redis_user_key(a), redis_user_key(b));
        assert_eq!(
            redis_user_key(AdmissionSubject::new(SearchTenantScope::Dedicated, user)),
            format!("search:admission:v2:user:{user}")
        );
        assert_eq!(
            redis_permit_keys(a),
            vec![
                REDIS_GLOBAL_KEY.to_string(),
                redis_user_key(a),
                format!("{}:aux", redis_user_key(a)),
                redis_tenant_key(Uuid::from_u128(0xa)),
            ]
        );
        assert_eq!(
            redis_permit_keys(AdmissionSubject::new(SearchTenantScope::Dedicated, user)).len(),
            3
        );
    }

    /// NAN-3299: the crash fence is each permit's own expiry score, pruned
    /// before every count, not a key TTL that every acquire refreshes.
    #[test]
    fn redis_acquire_and_release_scripts_keep_crash_and_race_fences() {
        assert!(ACQUIRE_LUA.contains("redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now)"));
        assert!(ACQUIRE_LUA.contains("redis.call('ZADD', key, expires, permit)"));
        assert!(!ACQUIRE_LUA.contains("INCR"));
        assert!(RELEASE_LUA.contains("redis.call('ZREM', KEYS[i], ARGV[1])"));
        assert!(!RELEASE_LUA.contains("DECR"));
        // Key TTL is idle GC only and must outlive the longest lease.
        assert!(
            REDIS_ADMISSION_KEY_TTL_SECS as u64 > permit_lease(QueryPriority::Analytics).as_secs()
        );
    }

    #[test]
    fn permit_leases_end_at_the_execution_ceiling_plus_slack() {
        assert_eq!(
            permit_lease(QueryPriority::Interactive),
            std::time::Duration::from_secs(300 + PERMIT_LEASE_SLACK_SECS)
        );
        assert_eq!(
            permit_lease(QueryPriority::Analytics),
            std::time::Duration::from_secs(3600 + PERMIT_LEASE_SLACK_SECS)
        );
    }

    #[test]
    fn auxiliary_lane_keeps_slots_for_the_rows_search() {
        assert_eq!(auxiliary_user_limit(1), 1);
        assert_eq!(auxiliary_user_limit(2), 1);
        assert_eq!(auxiliary_user_limit(5), 4);
        assert_eq!(auxiliary_user_limit(10), 8);
        assert_eq!(per_user_queue_limit(10), 20);
    }

    fn short_lease_controller(config: AdmissionConfig, lease_ms: u64) -> Arc<AdmissionController> {
        let mut controller = AdmissionController::new(config);
        controller.lease_override = Some(std::time::Duration::from_millis(lease_ms));
        Arc::new(controller)
    }

    fn one_slot_per_user() -> AdmissionConfig {
        AdmissionConfig {
            global_adhoc_limit: 10,
            shared_tenant_adhoc_limit: 10,
            per_user_limit: 1,
            max_queue_depth: 10,
            queue_timeout_ms: 5_000,
        }
    }

    /// NAN-3299: a permit that is never released (its holder vanished) is
    /// reclaimed once its lease ends; a waiter of the same user is admitted.
    #[tokio::test]
    async fn local_permit_never_released_is_reclaimed_after_its_lease() {
        let controller = short_lease_controller(one_slot_per_user(), 150);
        controller.start_drain_loop();
        let user = Uuid::now_v7();
        let leaked = controller
            .acquire("leaked", user, QueryPriority::Interactive)
            .await
            .unwrap();
        std::mem::forget(leaked);
        assert_eq!(controller.stats().await.active_adhoc, 1);

        let started = Instant::now();
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            controller.acquire("next", user, QueryPriority::Interactive),
        )
        .await
        .expect("orphaned permit is reclaimed within lease + drain cadence")
        .expect("admitted after reclaim");
        assert!(started.elapsed() >= std::time::Duration::from_millis(100));
        assert_eq!(controller.stats().await.active_adhoc, 1);
        drop(next);
        assert_eq!(controller.stats().await.active_adhoc, 0);
    }

    /// A permit released after its lease was reclaimed must not release the
    /// slot a newer permit now holds.
    #[tokio::test]
    async fn late_release_of_a_reclaimed_permit_does_not_double_free() {
        let controller = short_lease_controller(one_slot_per_user(), 50);
        let user = Uuid::now_v7();
        let stale = controller
            .acquire("stale", user, QueryPriority::Interactive)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let current = controller
            .acquire("current", user, QueryPriority::Interactive)
            .await
            .expect("expired lease is pruned on acquire");
        drop(stale);
        let stats = controller.stats().await;
        assert_eq!(stats.active_adhoc, 1);
        assert_eq!(stats.per_user_counts.len(), 1);
        assert_eq!(stats.per_user_counts[0].1, 1);
        drop(current);
        assert_eq!(controller.stats().await.active_adhoc, 0);
    }

    /// NAN-3299: one user's companions (histogram, field stats) cannot take
    /// the slots reserved for the rows search of the same run.
    #[tokio::test]
    async fn auxiliary_requests_cannot_starve_the_rows_search() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 30,
            shared_tenant_adhoc_limit: 30,
            per_user_limit: 4,
            max_queue_depth: 10,
            queue_timeout_ms: 5_000,
        }));
        controller.start_drain_loop();
        let subject = shared_subject(0xa, 1);
        let mut auxiliary = Vec::new();
        for index in 0..3 {
            auxiliary.push(
                controller
                    .acquire_subject_in_lane(
                        &format!("aux-{index}"),
                        subject,
                        false,
                        QueryPriority::Interactive,
                        AdmissionLane::Auxiliary,
                    )
                    .await
                    .expect("auxiliary within its cap"),
            );
        }
        let waiting_controller = Arc::clone(&controller);
        let fourth_auxiliary = tokio::spawn(async move {
            waiting_controller
                .acquire_subject_in_lane(
                    "aux-3",
                    subject,
                    false,
                    QueryPriority::Interactive,
                    AdmissionLane::Auxiliary,
                )
                .await
        });
        wait_for_depth(&controller, 1).await;

        let rows = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            controller.acquire_subject("rows", subject, false, QueryPriority::Interactive),
        )
        .await
        .expect("rows search is admitted at once")
        .expect("rows admitted");
        assert!(!fourth_auxiliary.is_finished());
        drop(rows);
        drop(auxiliary.pop());
        let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), fourth_auxiliary)
            .await
            .expect("auxiliary waiter admits after a release")
            .expect("join")
            .expect("admitted");
        drop((admitted, auxiliary));
    }

    /// Queued primary searches go before queued companions of equal priority.
    #[tokio::test]
    async fn queued_primary_is_served_before_queued_auxiliary() {
        let controller = AdmissionController::new(one_slot_per_user());
        let subject = shared_subject(0xa, 1);
        let holder = controller
            .acquire_subject("holder", subject, false, QueryPriority::Interactive)
            .await
            .unwrap();
        let controller = Arc::new(controller);
        let aux_controller = Arc::clone(&controller);
        let auxiliary = tokio::spawn(async move {
            aux_controller
                .acquire_subject_in_lane(
                    "aux",
                    subject,
                    false,
                    QueryPriority::Interactive,
                    AdmissionLane::Auxiliary,
                )
                .await
        });
        wait_for_depth(&controller, 1).await;
        let rows_controller = Arc::clone(&controller);
        let rows = tokio::spawn(async move {
            rows_controller
                .acquire_subject("rows", subject, false, QueryPriority::Interactive)
                .await
        });
        wait_for_depth(&controller, 2).await;
        assert_eq!(
            controller
                .queue_position_for_scope("rows", subject.scope())
                .await,
            Some(1),
            "the later rows search is first in line"
        );
        controller.start_drain_loop();
        drop(holder);
        let rows = tokio::time::timeout(std::time::Duration::from_secs(5), rows)
            .await
            .expect("rows admitted first")
            .expect("join")
            .expect("admitted");
        assert!(!auxiliary.is_finished());
        drop(rows);
        let auxiliary = tokio::time::timeout(std::time::Duration::from_secs(5), auxiliary)
            .await
            .expect("auxiliary admitted next")
            .expect("join")
            .expect("admitted");
        drop(auxiliary);
    }

    /// A user at their cap does not hold up another user's waiter behind it.
    #[tokio::test]
    async fn user_at_cap_does_not_block_other_users_waiters() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 2,
            shared_tenant_adhoc_limit: 2,
            per_user_limit: 1,
            max_queue_depth: 10,
            queue_timeout_ms: 5_000,
        }));
        controller.start_drain_loop();
        let busy = shared_subject(0xa, 1);
        let other = shared_subject(0xa, 2);
        let busy_permit = controller
            .acquire_subject("busy-1", busy, false, QueryPriority::Interactive)
            .await
            .unwrap();
        let filler = controller
            .acquire_subject(
                "filler",
                shared_subject(0xa, 3),
                false,
                QueryPriority::Interactive,
            )
            .await
            .unwrap();
        let busy_controller = Arc::clone(&controller);
        let busy_waiter = tokio::spawn(async move {
            busy_controller
                .acquire_subject("busy-2", busy, false, QueryPriority::Interactive)
                .await
        });
        wait_for_depth(&controller, 1).await;
        let other_controller = Arc::clone(&controller);
        let other_waiter = tokio::spawn(async move {
            other_controller
                .acquire_subject("other", other, false, QueryPriority::Interactive)
                .await
        });
        wait_for_depth(&controller, 2).await;

        // A cell slot frees; the older waiter's user is still at its cap.
        drop(filler);
        let other_permit = tokio::time::timeout(std::time::Duration::from_secs(5), other_waiter)
            .await
            .expect("other user admitted past the capped user's waiter")
            .expect("join")
            .expect("admitted");
        assert!(!busy_waiter.is_finished());
        drop((other_permit, busy_permit));
        let busy_second = tokio::time::timeout(std::time::Duration::from_secs(5), busy_waiter)
            .await
            .expect("capped user admitted after its own release")
            .expect("join")
            .expect("admitted");
        drop(busy_second);
    }

    /// NAN-3299 leak regression against a real Redis-compatible server: a
    /// permit whose release never arrives (pod killed mid-query) is pruned
    /// when its lease ends even while the same user keeps acquiring and
    /// releasing other permits. The retired counter design refreshed the key
    /// TTL on each of those acquires and so leaked the slot indefinitely.
    #[tokio::test]
    #[ignore = "requires NANOSIEM_ADMISSION_TEST_REDIS_URL for a disposable Redis/Dragonfly"]
    async fn redis_permit_never_released_is_pruned_after_its_lease() {
        let url = std::env::var("NANOSIEM_ADMISSION_TEST_REDIS_URL")
            .expect("NANOSIEM_ADMISSION_TEST_REDIS_URL must name a disposable database");
        let client = redis::Client::open(url).expect("create Redis client");
        let manager = client
            .get_connection_manager()
            .await
            .expect("connect to disposable Redis/Dragonfly");
        let mut cleanup = manager.clone();
        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut cleanup)
            .await
            .expect("clear disposable admission database before test");

        let mut controller = AdmissionController::new(AdmissionConfig {
            global_adhoc_limit: 10,
            shared_tenant_adhoc_limit: 10,
            per_user_limit: 2,
            max_queue_depth: 0,
            queue_timeout_ms: 100,
        });
        controller.lease_override = Some(std::time::Duration::from_millis(600));
        controller.set_redis(manager.clone()).await;
        let tenant = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa));
        let user = Uuid::from_u128(0x100);

        let leaked = controller
            .acquire_for_scope("leaked", tenant, user, QueryPriority::Interactive)
            .await
            .expect("first permit admits");
        // Simulate a killed pod: neither the local nor the Redis release runs.
        std::mem::forget(leaked);

        // The user stays busy: every acquire before expiry still sees the
        // orphaned permit, so a second concurrent one is refused.
        let deadline = Instant::now() + std::time::Duration::from_millis(400);
        while Instant::now() < deadline {
            let held = controller
                .acquire_for_scope("busy", tenant, user, QueryPriority::Interactive)
                .await
                .expect("one slot remains beside the orphan");
            let second = controller
                .acquire_for_scope("busy-2", tenant, user, QueryPriority::Interactive)
                .await;
            assert!(matches!(second, Err(AdmissionError::QueueFull { .. })));
            drop(held);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let first = controller
            .acquire_for_scope("after-1", tenant, user, QueryPriority::Interactive)
            .await
            .expect("orphan pruned: first slot");
        let second = controller
            .acquire_for_scope("after-2", tenant, user, QueryPriority::Interactive)
            .await
            .expect("orphan pruned: both of the user's slots are free again");
        let user_members: i64 = redis::cmd("ZCARD")
            .arg(redis_user_key(AdmissionSubject::new(tenant, user)))
            .query_async(&mut cleanup)
            .await
            .expect("read user leases");
        assert_eq!(user_members, 2);
        drop((first, second));
    }

    #[cfg(feature = "enterprise")]
    /// Exact distributed contract check for the Redis-compatible service used
    /// by enterprise-shared Search. Run only against a disposable, dedicated
    /// database because the fixed cell key is deliberately shared by every
    /// replica in one deployment.
    #[tokio::test]
    #[ignore = "requires NANOSIEM_ADMISSION_TEST_REDIS_URL for a disposable Redis/Dragonfly"]
    async fn enterprise_shared_dragonfly_enforces_cell_tenant_user_and_atomic_release() {
        let url = std::env::var("NANOSIEM_ADMISSION_TEST_REDIS_URL")
            .expect("NANOSIEM_ADMISSION_TEST_REDIS_URL must name a disposable database");
        let client = redis::Client::open(url).expect("create Redis client");
        let manager = client
            .get_connection_manager()
            .await
            .expect("connect to disposable Redis/Dragonfly");
        let mut cleanup = manager.clone();
        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut cleanup)
            .await
            .expect("clear disposable admission database before test");

        let config = AdmissionConfig {
            global_adhoc_limit: 3,
            shared_tenant_adhoc_limit: 2,
            per_user_limit: 1,
            max_queue_depth: 0,
            queue_timeout_ms: 100,
        };
        let first_replica = AdmissionController::new(config.clone());
        let second_replica = AdmissionController::new(config);
        first_replica.set_redis(manager.clone()).await;
        second_replica.set_redis(manager.clone()).await;

        let tenant_a = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa));
        let tenant_b = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb));
        let shared_raw_user = Uuid::from_u128(0x100);
        let tenant_a_second_user = Uuid::from_u128(0x200);
        let tenant_a_third_user = Uuid::from_u128(0x300);
        let tenant_b_second_user = Uuid::from_u128(0x400);

        let permit_a1 = first_replica
            .acquire_for_scope("a1", tenant_a, shared_raw_user, QueryPriority::Interactive)
            .await
            .expect("tenant A/user 1 should admit on replica one");
        let duplicate_user = second_replica
            .acquire_for_scope(
                "a1-duplicate",
                tenant_a,
                shared_raw_user,
                QueryPriority::Interactive,
            )
            .await;
        // Per-user overflow is queueable; with no queue it is QueueFull.
        assert!(matches!(
            duplicate_user,
            Err(AdmissionError::QueueFull { depth: 0 })
        ));

        let permit_a2 = second_replica
            .acquire_for_scope(
                "a2",
                tenant_a,
                tenant_a_second_user,
                QueryPriority::Interactive,
            )
            .await
            .expect("tenant A/user 2 should consume its second tenant slot");
        let tenant_full = first_replica
            .acquire_for_scope(
                "a3",
                tenant_a,
                tenant_a_third_user,
                QueryPriority::Interactive,
            )
            .await;
        assert!(matches!(
            tenant_full,
            Err(AdmissionError::QueueFull { depth: 0 })
        ));

        // The same raw user UUID in another tenant has a separate user key and
        // can consume the final cell-wide slot.
        let permit_b1 = second_replica
            .acquire_for_scope("b1", tenant_b, shared_raw_user, QueryPriority::Interactive)
            .await
            .expect("tenant B should use the remaining cell slot");
        let cell_full = first_replica
            .acquire_for_scope(
                "b2",
                tenant_b,
                tenant_b_second_user,
                QueryPriority::Interactive,
            )
            .await;
        assert!(matches!(
            cell_full,
            Err(AdmissionError::QueueFull { depth: 0 })
        ));

        let cell_count: i64 = redis::cmd("ZCARD")
            .arg(REDIS_GLOBAL_KEY)
            .query_async(&mut cleanup)
            .await
            .expect("read cell count");
        let tenant_a_count: i64 = redis::cmd("ZCARD")
            .arg(redis_tenant_key(Uuid::from_u128(0xa)))
            .query_async(&mut cleanup)
            .await
            .expect("read tenant A count");
        let tenant_b_count: i64 = redis::cmd("ZCARD")
            .arg(redis_tenant_key(Uuid::from_u128(0xb)))
            .query_async(&mut cleanup)
            .await
            .expect("read tenant B count");
        assert_eq!((cell_count, tenant_a_count, tenant_b_count), (3, 2, 1));

        drop((permit_a1, permit_a2, permit_b1));
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let remaining: i64 = redis::cmd("EXISTS")
                    .arg(REDIS_GLOBAL_KEY)
                    .arg(redis_tenant_key(Uuid::from_u128(0xa)))
                    .arg(redis_tenant_key(Uuid::from_u128(0xb)))
                    .query_async(&mut cleanup)
                    .await
                    .expect("read released admission keys");
                if remaining == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("atomic permit release should remove cell and tenant keys");
    }
}
