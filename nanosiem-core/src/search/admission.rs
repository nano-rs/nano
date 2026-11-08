// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search query admission control
//!
//! Priority-based admission controller using either:
//! - **Redis leases** for cluster-wide limits (active/active deployments)
//! - **A local lease ledger** as fallback (single-instance or Redis unavailable)
//!
//! Detection/NRT queries bypass the queue entirely. Interactive/Analytics queries
//! are subject to global and per-user concurrency limits; any overflow waits in
//! a bounded fair queue. Every permit is a lease that expires at the priority's
//! execution ceiling plus slack, so a permit whose holder died is reclaimed
//! instead of leaking (NAN-3299).
//!
//! **Queue, not reject (NAN-4664).** Overflow waits in a bounded fair queue
//! for at most the request's wait budget ([`ADMISSION_WAIT_HEADER`], default
//! [`DEFAULT_ADMISSION_WAIT`], capped at `queue_timeout_ms`); a refusal
//! (`QueueTimeout`, `QueueFull`, 429 with `Retry-After`) comes only when that
//! budget ends or the queue is full. Concurrency limits are unchanged. The
//! drain serves waiters in [`service_order`]: humans before agents
//! (NAN-4703), priority, rows searches before their companions (NAN-3299),
//! then round-robin across principals. A caller that disconnects leaves the
//! queue at once and its work is never started.
//!
//! **Cancellation safety (NAN-4915).** The drain hands a waiter the permit
//! itself, so a waiter that vanished between the drain's check and its send
//! drops the permit (and with it every lease) instead of leaking a slot.

use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Maximum concurrent queries per user. Overflow waits in the queue.
    pub per_user_limit: u32,
    /// Maximum queue depth before rejecting new queries
    pub max_queue_depth: u32,
    /// Queue timeout in milliseconds
    pub queue_timeout_ms: u64,
}

/// NAN-3299: one Search page run holds a rows search, a histogram and a
/// field-stats request at once (plus a rerun's overlap while the superseded
/// run is cancelled). Five permits per user failed single searches with 429.
pub const DEFAULT_PER_USER_LIMIT: u32 = 10;

/// NAN-3299 / NAN-4664: waiters one principal (a user or an API key) may
/// queue beyond their running searches. A per-principal overflow waits
/// instead of failing; the bound only keeps one principal from filling the
/// whole queue, so other principals can still enqueue. `queue_share` is the
/// bound of the queue the principal waits in (`max_queue_depth`).
///
/// The old bound (`2 x per_user_limit`) refused a closed-loop fleet of 16
/// agents sharing one login at the DB default of 5 permits: 5 running plus
/// 10 queued left the 16th a 429 (NAN-4664 bakeoff, 12 of 160 hunts).
fn principal_queue_limit(per_user_limit: u32, queue_share: u32) -> u32 {
    per_user_limit
        .saturating_mul(2)
        .max(queue_share / 2)
        .min(queue_share.max(1))
        .max(1)
}

// ============================================================================
// Query class (NAN-4703)
// ============================================================================

/// Who a search is for (NAN-4703). A credential the server knows belongs to
/// an agent ([`is_agent_api_key_name`]) is always the agent class; any other
/// caller opts in with [`QUERY_CLASS_HEADER`] (see [`resolve_query_class`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum QueryClass {
    /// An analyst at a screen (and every caller that names no class).
    #[default]
    Human,
    /// An automated agent's search: a hard cap ([`agent_class_limit`]) so it
    /// never takes the share reserved for humans, and the lowest priority in
    /// the queue. No extra budget: deadlines and result caps are the human
    /// ones.
    Agent,
}

impl QueryClass {
    pub const fn label(self) -> &'static str {
        match self {
            QueryClass::Human => "human",
            QueryClass::Agent => "agent",
        }
    }
}

/// Request header naming a search's class: `agent` opts into the agent
/// class. Declaring it only ever lowers the caller's share, so the header
/// is trusted as sent; anything else is [`QueryClass::Human`].
pub const QUERY_CLASS_HEADER: &str = "x-nano-query-class";

/// The class a [`QUERY_CLASS_HEADER`] value names.
pub fn parse_query_class_header(value: Option<&str>) -> QueryClass {
    match value.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("agent") => QueryClass::Agent,
        _ => QueryClass::Human,
    }
}

/// NAN-4703: the name prefix nano Desktop gives every API key it mints for
/// its agents (agent tools/MCP, recon, hunt runner, hunt sweep). Desktop
/// mints no other keys; an analyst's desktop session is a JWT.
pub const DESKTOP_AGENT_KEY_NAME_PREFIX: &str = "nano Desktop \u{2014} ";

/// Whether an API key is an agent's credential, from its server-stored name.
pub fn is_agent_api_key_name(name: &str) -> bool {
    name.trim_start().starts_with(DESKTOP_AGENT_KEY_NAME_PREFIX)
}

/// The class of a request: an agent credential is always [`QueryClass::Agent`]
/// whatever the header says (a header never upgrades an agent to human);
/// otherwise the [`QUERY_CLASS_HEADER`] value decides.
pub fn resolve_query_class(agent_credential: bool, header: Option<&str>) -> QueryClass {
    if agent_credential {
        QueryClass::Agent
    } else {
        parse_query_class_header(header)
    }
}

/// Slots of the process's ceiling that agent-class searches never take: a
/// quarter, at least one. A ceiling of one slot cannot reserve any.
pub const fn human_reserved_slots(scope_limit: u32) -> u32 {
    if scope_limit <= 1 {
        return 0;
    }
    let quarter = scope_limit / 4;
    if quarter == 0 {
        1
    } else {
        quarter
    }
}

/// The most permits agent-class searches hold at once: the ceiling less
/// [`human_reserved_slots`] (at least one).
pub const fn agent_class_limit(scope_limit: u32) -> u32 {
    let limit = scope_limit.saturating_sub(human_reserved_slots(scope_limit));
    if limit == 0 {
        1
    } else {
        limit
    }
}

tokio::task_local! {
    /// The current request's query class (see [`with_query_class`]).
    static ADMISSION_QUERY_CLASS: QueryClass;
}

/// Run `future` as a `class` search: every admission inside it is taken in
/// that class.
pub async fn with_query_class<F: std::future::Future>(class: QueryClass, future: F) -> F::Output {
    ADMISSION_QUERY_CLASS.scope(class, future).await
}

/// The current request's query class ([`QueryClass::Human`] outside any scope).
pub fn current_query_class() -> QueryClass {
    ADMISSION_QUERY_CLASS
        .try_with(|class| *class)
        .unwrap_or_default()
}

// ============================================================================
// Per-request wait budget (NAN-4664)
// ============================================================================

/// Request header carrying a caller's admission wait budget in milliseconds.
/// Agent and API callers set a longer budget (up to the configured
/// `queue_timeout_ms`) to queue instead of failing; `0` means "fail fast
/// when no slot is free".
pub const ADMISSION_WAIT_HEADER: &str = "x-nano-admission-wait-ms";

/// The wait budget of an HTTP search that names none. Longer than the
/// interactive hand-off deadline (45 s), so a browser search that waits
/// becomes the durable job the UI follows instead of a 429, and well above a
/// fleet's expected wait (16 closed-loop agents over 5 permits at a 3.5 s
/// p50 queue for ~8 s each).
pub const DEFAULT_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

tokio::task_local! {
    /// The current request's admission wait budget (see [`with_wait_budget`]).
    static ADMISSION_WAIT_BUDGET: std::time::Duration;
}

/// Run `future` with `budget` as its admission wait budget. Every admission
/// inside it waits at most `budget`, capped by the configured
/// `queue_timeout_ms`. Outside any scope (internal callers: jobs, SOAR,
/// shadow investigation) the configured `queue_timeout_ms` applies as before.
pub async fn with_wait_budget<F: std::future::Future>(
    budget: std::time::Duration,
    future: F,
) -> F::Output {
    ADMISSION_WAIT_BUDGET.scope(budget, future).await
}

/// Run `future` free of any request's wait budget: background work that
/// outlives its HTTP request (an async job) waits up to the configured
/// `queue_timeout_ms`, as internal callers always have.
pub async fn without_wait_budget<F: std::future::Future>(future: F) -> F::Output {
    ADMISSION_WAIT_BUDGET
        .scope(std::time::Duration::MAX, future)
        .await
}

/// The current request's admission wait budget, if a scope is active.
pub fn current_wait_budget() -> Option<std::time::Duration> {
    ADMISSION_WAIT_BUDGET.try_with(|budget| *budget).ok()
}

/// Parse an [`ADMISSION_WAIT_HEADER`] value. `None` (use
/// [`DEFAULT_ADMISSION_WAIT`]) for an absent or unparsable value; the
/// controller caps any value at the configured `queue_timeout_ms`.
pub fn parse_wait_budget_header(value: Option<&str>) -> Option<std::time::Duration> {
    value
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
}

/// The budget an HTTP search runs with: the caller's header value, else
/// [`DEFAULT_ADMISSION_WAIT`]. (The cap is applied at admission, where the
/// live config is known.)
pub fn request_wait_budget(header: Option<&str>) -> std::time::Duration {
    parse_wait_budget_header(header).unwrap_or(DEFAULT_ADMISSION_WAIT)
}

/// The wait one admission gets: the request's budget capped at the
/// configured `queue_timeout_ms`, or that cap outside any budget scope.
fn effective_wait(budget: Option<std::time::Duration>, queue_timeout_ms: u64) -> std::time::Duration {
    let cap = std::time::Duration::from_millis(queue_timeout_ms);
    budget.map_or(cap, |budget| budget.min(cap))
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
    /// NAN-4703: an agent-class search whose cluster-wide admission (Redis)
    /// is configured but unreachable. The local ledger counts one replica
    /// only, so it could not hold the human reserve; agents fail closed.
    #[error("Search admission is unavailable")]
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

/// The principal an admission is counted against.
type AdmissionSubject = uuid::Uuid;

struct LocalLease {
    subject: AdmissionSubject,
    lane: AdmissionLane,
    class: QueryClass,
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
    per_user: HashMap<AdmissionSubject, u32>,
    per_user_auxiliary: HashMap<AdmissionSubject, u32>,
    /// NAN-4703: agent-class permits of the process.
    agents: u32,
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

    fn agent_count(&self) -> u32 {
        self.agents
    }

    fn insert(
        &mut self,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        class: QueryClass,
        expires_at: Instant,
    ) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        self.leases.insert(
            id,
            LocalLease {
                subject,
                lane,
                class,
                expires_at,
            },
        );
        if class == QueryClass::Agent {
            self.agents += 1;
        }
        increment(&mut self.per_user, subject);
        if lane == AdmissionLane::Auxiliary {
            increment(&mut self.per_user_auxiliary, subject);
        }
        id
    }

    /// Extend a live lease to `expires_at`. False when it is gone (released
    /// or already reclaimed), which ends its renewal.
    fn renew(&mut self, id: u64, expires_at: Instant) -> bool {
        match self.leases.get_mut(&id) {
            Some(lease) => {
                lease.expires_at = expires_at;
                true
            }
            None => false,
        }
    }

    /// Release one lease. False when it was already reclaimed as expired.
    fn release(&mut self, id: u64) -> bool {
        let Some(lease) = self.leases.remove(&id) else {
            return false;
        };
        decrement(&mut self.per_user, &lease.subject);
        if lease.lane == AdmissionLane::Auxiliary {
            decrement(&mut self.per_user_auxiliary, &lease.subject);
        }
        if lease.class == QueryClass::Agent {
            self.agents = self.agents.saturating_sub(1);
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
                subject = %subject,
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
/// from the retired counter strings (`search:admission:active`,
/// `search:admission:user:*`), which expire on their own TTL; during a
/// rolling deploy old and new replicas therefore count separate budgets.
const REDIS_GLOBAL_KEY: &str = "search:admission:v2:active";

/// NAN-4703: every agent-class permit of the deployment.
const REDIS_AGENT_KEY: &str = "search:admission:v2:agent";

fn redis_user_key(subject: AdmissionSubject) -> String {
    format!("search:admission:v2:user:{subject}")
}

fn redis_user_auxiliary_key(subject: AdmissionSubject) -> String {
    format!("{}:aux", redis_user_key(subject))
}

/// Every key one permit is recorded in, in the order `ACQUIRE_LUA` expects:
/// global, user, user-auxiliary, then for an agent-class permit the agent key.
fn redis_permit_keys(subject: AdmissionSubject, class: QueryClass) -> Vec<String> {
    let mut keys = vec![
        REDIS_GLOBAL_KEY.to_string(),
        redis_user_key(subject),
        redis_user_auxiliary_key(subject),
    ];
    if class == QueryClass::Agent {
        keys.push(REDIS_AGENT_KEY.to_string());
    }
    keys
}

/// Idle-key garbage collection only. Correctness comes from each member's
/// expiry score, so refreshing this TTL on every acquire can no longer pin a
/// leaked permit; it must stay above the longest lease (Analytics).
const REDIS_ADMISSION_KEY_TTL_SECS: i64 = 7800;

/// Atomic prune + check + lease for one permit.
///
/// KEYS[1] = global, KEYS[2] = user, KEYS[3] = user auxiliary,
/// KEYS[4] = agent (agent class only, NAN-4703)
/// ARGV[1] = now (Unix ms), ARGV[2] = lease expiry (Unix ms), ARGV[3] = permit id,
/// ARGV[4] = global limit, ARGV[5] = user limit,
/// ARGV[6] = auxiliary user limit, or -1 for a primary request,
/// ARGV[7] = key TTL seconds,
/// ARGV[8] = agent-class limit, or -1 for a human-class request
///
/// Returns 1 admitted, -1 global full, -2 user full, -4 the agent class
/// full. Every "full" answer is queueable; expired leases are pruned before
/// counting.
const ACQUIRE_LUA: &str = r#"
local now = tonumber(ARGV[1])
local expires = tonumber(ARGV[2])
local permit = ARGV[3]
local global_limit = tonumber(ARGV[4])
local user_limit = tonumber(ARGV[5])
local auxiliary_limit = tonumber(ARGV[6])
local key_ttl = tonumber(ARGV[7])
local agent_limit = tonumber(ARGV[8])
local agent_key = nil
if agent_limit >= 0 then
    agent_key = KEYS[4]
end

for i = 1, #KEYS do
    redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now)
end

if redis.call('ZCARD', KEYS[2]) >= user_limit then
    return -2
end
if auxiliary_limit >= 0 and redis.call('ZCARD', KEYS[3]) >= auxiliary_limit then
    return -2
end
if agent_key and redis.call('ZCARD', agent_key) >= agent_limit then
    return -4
end
if redis.call('ZCARD', KEYS[1]) >= global_limit then
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
if agent_key then
    lease(agent_key)
end
return 1
"#;

/// NAN-4928 review P1: extend a live permit's lease in every key that still
/// holds it (ARGV[1] permit id, ARGV[2] new expiry Unix ms, ARGV[3] key TTL).
/// A permit already pruned is not resurrected. Returns how many keys held it.
const RENEW_LUA: &str = r#"
local renewed = 0
for i = 1, #KEYS do
    if redis.call('ZSCORE', KEYS[i], ARGV[1]) then
        redis.call('ZADD', KEYS[i], 'XX', ARGV[2], ARGV[1])
        redis.call('EXPIRE', KEYS[i], tonumber(ARGV[3]))
        renewed = renewed + 1
    end
end
return renewed
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
    GlobalFull,
    UserFull,
    /// NAN-4703: the agent class is at its cap (humans may still admit).
    AgentFull,
}

// ============================================================================
// AdmissionPermit
// ============================================================================

struct RedisLease {
    conn: redis::aio::ConnectionManager,
    permit_id: String,
}

/// RAII guard — dropping it frees an admission slot and wakes the next queued search.
///
/// The local ledger lease is always released; when Redis admitted the permit,
/// `drop` also spawns a fire-and-forget atomic Redis release. Lease expiry
/// (local and Redis) recovers permits after process loss or a lost release.
pub struct AdmissionPermit {
    subject: AdmissionSubject,
    class: QueryClass,
    local_lease: Option<u64>,
    ledger: Arc<std::sync::Mutex<LocalLedger>>,
    slot_available: Arc<Notify>,
    redis: Option<RedisLease>,
    /// NAN-4928 review P1: renews the lease while the permit lives, so a
    /// search that runs several queries (lateral hops, companions) never
    /// outlives its slot. Aborted on drop; a crashed holder stops renewing
    /// and its lease is reclaimed one lease later.
    renewer: Option<tokio::task::JoinHandle<()>>,
}

/// How often a live permit renews its lease: a third of the lease, so two
/// renewals can be missed before it lapses.
fn renew_interval(lease: std::time::Duration) -> std::time::Duration {
    (lease / 3).max(std::time::Duration::from_millis(10))
}

fn spawn_lease_renewer(
    ledger: Arc<std::sync::Mutex<LocalLedger>>,
    lease_id: u64,
    lease: std::time::Duration,
    redis: Option<(redis::aio::ConnectionManager, Vec<String>, String)>,
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(async move {
        let mut redis = redis;
        loop {
            tokio::time::sleep(renew_interval(lease)).await;
            if !lock_ledger(&ledger).renew(lease_id, Instant::now() + lease) {
                return;
            }
            if let Some((conn, keys, permit_id)) = redis.as_mut() {
                let expires_ms = unix_millis_now().saturating_add(lease.as_millis() as i64);
                let mut command = redis::cmd("EVAL");
                command
                    .arg(RENEW_LUA)
                    .arg(keys.len())
                    .arg(&*keys)
                    .arg(&*permit_id)
                    .arg(expires_ms)
                    .arg(REDIS_ADMISSION_KEY_TTL_SECS);
                match command.query_async::<i64>(conn).await {
                    Ok(0) => {
                        tracing::warn!("search admission Redis lease was pruned before renewal");
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(error = %error, "search admission Redis lease renewal failed; retrying");
                    }
                }
            }
        }
    }))
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if let Some(renewer) = self.renewer.take() {
            renewer.abort();
        }
        let Some(lease_id) = self.local_lease.take() else {
            // Detection/NRT bypass permits hold no slot.
            return;
        };

        let active = {
            let mut ledger = lock_ledger(&self.ledger);
            if !ledger.release(lease_id) {
                tracing::warn!(
                    subject = %self.subject,
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
            let class = self.class;
            let slot_available = self.slot_available.clone();
            tokio::spawn(async move {
                let keys = redis_permit_keys(subject, class);
                let mut command = redis::cmd("EVAL");
                command
                    .arg(RELEASE_LUA)
                    .arg(keys.len())
                    .arg(&keys)
                    .arg(&permit_id);
                if let Err(error) = command.query_async::<i64>(&mut conn).await {
                    tracing::error!(
                        error = %error,
                        "search admission Redis permit release failed; lease expiry recovers it"
                    );
                }
                // NAN-4915: the synchronous notify above runs the drain
                // before this release lands, so in Redis mode the drain read
                // the stale cluster-wide count and judged the pool full. Wake
                // it again now that Redis reflects the released slot.
                slot_available.notify_one();
            });
        }
    }
}

/// NAN-4703: whether a new agent-class waiter is refused, and at which depth.
/// Agent waiters stop at [`agent_class_limit`] of the queue, so agents never
/// take the places in line kept for humans.
fn agent_queue_rejection(waiters: &[QueuedSearch], max_queue_depth: u32) -> Option<u32> {
    let agents = waiters
        .iter()
        .filter(|queued| queued.class == QueryClass::Agent)
        .count();
    let limit = agent_class_limit(max_queue_depth);
    (agents >= limit as usize).then_some(limit)
}

/// A queued search waiting for admission
struct QueuedSearch {
    /// Unique, monotonically increasing per controller: FIFO order and the
    /// handle a waiter's [`QueuedGuard`] removes itself by. `job_id` is
    /// caller-supplied and need not be unique.
    seq: u64,
    job_id: String,
    subject: AdmissionSubject,
    priority: QueryPriority,
    lane: AdmissionLane,
    class: QueryClass,
    /// Fair-queue tag among principals (see [`WaitQueue`]).
    principal_tag: u64,
    /// Sender to notify when admitted. It carries the permit itself, so a
    /// waiter that left before the send drops it and no lease leaks.
    tx: oneshot::Sender<Result<AdmissionPermit, AdmissionError>>,
}

/// NAN-4664: the bounded admission queue, served by start-time fair queueing
/// across principals.
///
/// Every waiter carries a **principal tag** taken at enqueue: one past the
/// later of the virtual clock and its principal's newest queued tag. The
/// clock advances to the tag of each admitted waiter, so a principal
/// arriving late starts level with the others' next turn instead of behind
/// their whole backlog, and one that was just served goes to the back. The
/// drain serves human-class before agent-class (NAN-4703), higher priority
/// first, then primary before auxiliary (NAN-3299), then the lowest
/// principal tag (round-robin across principals: one agent with a deep
/// backlog cannot starve other agents or analysts), then FIFO.
///
/// Tags are tickets of their principal, not of one search:
/// [`service_order`] hands a principal's tickets to its waiters in the
/// principal's own order, so its Interactive search can use the ticket its
/// older Analytics search took. Memory is bounded by `max_queue_depth`
/// whatever the arrival rate.
#[derive(Default)]
struct WaitQueue {
    next_seq: u64,
    waiters: Vec<QueuedSearch>,
    /// Principal tag of the latest admission.
    principal_clock: u64,
}

impl WaitQueue {
    fn len(&self) -> usize {
        self.waiters.len()
    }

    fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    /// Enqueue `search` (its `seq` and tag are assigned here); returns its seq.
    fn push(&mut self, mut search: QueuedSearch) -> u64 {
        self.next_seq += 1;
        search.seq = self.next_seq;
        let principal_last = self
            .waiters
            .iter()
            .filter(|queued| queued.subject == search.subject)
            .map(|queued| queued.principal_tag)
            .max()
            .unwrap_or(0);
        search.principal_tag = self.principal_clock.max(principal_last) + 1;
        self.waiters.push(search);
        self.next_seq
    }

    /// Advance the virtual clock past an admitted waiter's tag.
    fn record_admitted(&mut self, search: &QueuedSearch) {
        self.principal_clock = self.principal_clock.max(search.principal_tag);
    }

    /// Restart the clock once nobody waits (bounded state).
    fn prune_clocks(&mut self) {
        if self.waiters.is_empty() {
            self.principal_clock = 0;
        }
    }

    /// Drop waiters whose caller is gone (a disconnected client whose
    /// guard has not run yet). Returns how many.
    fn purge_abandoned(&mut self) -> usize {
        let before = self.waiters.len();
        self.waiters.retain(|queued| !queued.tx.is_closed());
        before - self.waiters.len()
    }

    fn take(&mut self, seq: u64) -> Option<QueuedSearch> {
        let index = self.waiters.iter().position(|queued| queued.seq == seq)?;
        Some(self.waiters.swap_remove(index))
    }
}

/// A waiter's rank: every human-class search before any agent-class one
/// (NAN-4703: agents are the lowest priority), then by priority.
fn queue_rank(queued: &QueuedSearch) -> u8 {
    let class = match queued.class {
        QueryClass::Human => 0,
        QueryClass::Agent => 1,
    };
    class * 16 + queued.priority.ordinal()
}

/// The waiters' service order, as indices into `queue`, first served first
/// (see [`WaitQueue`]). Normalizes the tags in place: each principal's tags
/// are handed to its waiters in its own (rank, lane, FIFO) order. The queue
/// is bounded (a few hundred entries at most), so this runs on every drain.
fn service_order(queue: &mut [QueuedSearch]) -> Vec<usize> {
    let mut principals: HashMap<AdmissionSubject, Vec<usize>> = HashMap::new();
    for (index, queued) in queue.iter().enumerate() {
        principals.entry(queued.subject).or_default().push(index);
    }
    for mut indices in principals.into_values() {
        let mut tags: Vec<u64> = indices
            .iter()
            .map(|&index| queue[index].principal_tag)
            .collect();
        tags.sort_unstable();
        indices.sort_by_key(|&index| {
            (
                queue_rank(&queue[index]),
                queue[index].lane.ordinal(),
                queue[index].seq,
            )
        });
        for (index, tag) in indices.into_iter().zip(tags) {
            queue[index].principal_tag = tag;
        }
    }
    let mut order: Vec<usize> = (0..queue.len()).collect();
    order.sort_by_key(|&index| {
        let queued = &queue[index];
        (
            queue_rank(queued),
            queued.lane.ordinal(),
            queued.principal_tag,
            queued.seq,
        )
    });
    order
}

fn lock_queue(queue: &std::sync::Mutex<WaitQueue>) -> std::sync::MutexGuard<'_, WaitQueue> {
    queue.lock().unwrap_or_else(|poisoned| {
        tracing::error!("search admission queue was poisoned; repairing");
        poisoned.into_inner()
    })
}

/// NAN-4664 / NAN-4915: removes a waiter from the queue when its `acquire`
/// future is dropped (client disconnect, deadline hand-off, task abort) so a
/// dead waiter never holds a queue slot and is never admitted.
struct QueuedGuard<'a> {
    queue: &'a std::sync::Mutex<WaitQueue>,
    seq: u64,
    armed: bool,
}

impl Drop for QueuedGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let depth = {
            let mut queue = lock_queue(self.queue);
            if queue.take(self.seq).is_some() {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "client_gone")
                    .increment(1);
            }
            queue.len()
        };
        gauge!("nanosiem_search_queue_depth").set(depth as f64);
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
/// all instances via atomic Lua scripts over per-permit leases. The local
/// ledger is always maintained as a fallback and for Prometheus gauges.
pub struct AdmissionController {
    config: Mutex<AdmissionConfig>,
    /// Local permit leases. The same short critical section serializes the
    /// local check+lease and release paths.
    ledger: Arc<std::sync::Mutex<LocalLedger>>,
    queue: std::sync::Mutex<WaitQueue>,
    /// Test hook: a fixed lease instead of the per-priority one.
    lease_override: Option<std::time::Duration>,
    slot_available: Arc<Notify>,
    // Optional Redis connection for cluster-wide counters
    redis_conn: Mutex<Option<redis::aio::ConnectionManager>>,
    /// NAN-4703: the deployment configured Redis admission (`REDIS_URL`),
    /// even if the connection failed at boot. Agent-class searches then
    /// never take the per-replica local fallback.
    redis_expected: std::sync::atomic::AtomicBool,
    /// NAN-4928 review P1: when Redis admission (configured) started failing.
    /// Cleared by the next answer Redis gives.
    redis_failing_since: std::sync::Mutex<Option<Instant>>,
    /// How long human searches keep a bounded local fallback through a Redis
    /// outage before failing closed ([`REDIS_OUTAGE_GRACE_ENV`]).
    redis_outage_grace: std::time::Duration,
    /// Search replicas sharing the global limit ([`SEARCH_REPLICAS_ENV`]):
    /// during the grace each replica admits at most `global / replicas`.
    replica_count: u32,
}

/// Seconds a Redis admission outage may last before ad-hoc searches fail
/// closed (default 30). During the grace each replica admits locally up to
/// its share of the global limit.
pub const REDIS_OUTAGE_GRACE_ENV: &str = "NANO_SEARCH_ADMISSION_REDIS_GRACE_SECS";
/// Number of Search replicas that share one Redis admission budget
/// (default 1). Used only to bound the local fallback during a Redis
/// outage, so N replicas together never exceed the configured global limit.
pub const SEARCH_REPLICAS_ENV: &str = "NANO_SEARCH_REPLICAS";

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

impl AdmissionController {
    /// Create a new admission controller with the given configuration
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config: Mutex::new(config),
            ledger: Arc::new(std::sync::Mutex::new(LocalLedger::default())),
            queue: std::sync::Mutex::new(WaitQueue::default()),
            lease_override: None,
            slot_available: Arc::new(Notify::new()),
            redis_conn: Mutex::new(None),
            redis_expected: std::sync::atomic::AtomicBool::new(false),
            redis_failing_since: std::sync::Mutex::new(None),
            redis_outage_grace: std::time::Duration::from_secs(
                env_u64(REDIS_OUTAGE_GRACE_ENV).unwrap_or(30),
            ),
            replica_count: env_u64(SEARCH_REPLICAS_ENV)
                .map(|n| n.clamp(1, 1024) as u32)
                .unwrap_or(1),
        }
    }

    /// NAN-4703: record that this deployment configured Redis admission.
    /// Without a working connection, agent-class searches fail closed
    /// instead of counting against this replica's local ledger only
    /// (humans keep the local fallback).
    pub fn expect_redis(&self) {
        self.redis_expected
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set the Redis connection for cluster-wide admission limits.
    /// When set, limits are enforced globally via Redis leases; human
    /// searches fall back to the local ledger when Redis errors.
    pub async fn set_redis(&self, conn: redis::aio::ConnectionManager) {
        *self.redis_conn.lock().await = Some(conn);
        tracing::info!("Admission controller: Redis cluster-wide limits enabled");
    }

    /// Acquire an admission permit for executing a search query.
    ///
    /// - Detection/NRT: Always admitted immediately (bypasses queue).
    /// - Interactive/Analytics: Subject to per-user and global limits.
    ///   If any limit is full, the query waits in the fair queue.
    pub async fn acquire(
        &self,
        job_id: &str,
        user_id: uuid::Uuid,
        priority: QueryPriority,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.acquire_in_lane(job_id, user_id, priority, AdmissionLane::Primary)
            .await
    }

    fn lease_for(&self, priority: QueryPriority) -> std::time::Duration {
        self.lease_override
            .unwrap_or_else(|| permit_lease(priority))
    }

    /// [`Self::acquire`] for a request in an explicit lane. Search
    /// companions (histogram, field stats) use [`AdmissionLane::Auxiliary`].
    #[tracing::instrument(name = "search.admission.wait", skip_all)]
    pub async fn acquire_in_lane(
        &self,
        job_id: &str,
        subject: uuid::Uuid,
        priority: QueryPriority,
        lane: AdmissionLane,
    ) -> Result<AdmissionPermit, AdmissionError> {
        // Detection/NRT always bypass
        if priority.bypasses_queue() {
            counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                .increment(1);
            return Ok(AdmissionPermit {
                subject,
                class: QueryClass::Human,
                local_lease: None,
                ledger: self.ledger.clone(),
                slot_available: self.slot_available.clone(),
                redis: None,
                renewer: None,
            });
        }

        // Try immediate admission, but never barge past waiters: with anyone
        // queued, a new arrival takes its turn through the fair drain. In a
        // closed-loop fleet an agent re-acquires the instant it releases, so
        // barging let it re-take its own freed slot ahead of every waiter
        // (NAN-4664). The drain still admits it at once when the waiters
        // ahead are blocked on their own principal or class caps.
        let class = current_query_class();
        let (queue_idle, human_waiting) = {
            let mut queue = lock_queue(&self.queue);
            queue.purge_abandoned();
            let human_waiting = queue
                .waiters
                .iter()
                .any(|queued| queued.class == QueryClass::Human);
            (queue.is_empty(), human_waiting)
        };
        // A fail-fast caller (budget 0) never waits, so it only ever takes a
        // slot that is free right now. NAN-4703: a fail-fast agent never
        // takes it past a waiting human (agents are the lowest priority).
        let fail_fast = current_wait_budget().is_some_and(|budget| budget.is_zero());
        if queue_idle || (fail_fast && !(class == QueryClass::Agent && human_waiting)) {
            match self.try_admit(subject, priority, lane, class).await? {
                AdmissionAttempt::Admitted(permit) => {
                    counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                        .increment(1);
                    self.update_gauges().await;
                    return Ok(permit);
                }
                AdmissionAttempt::GlobalFull
                | AdmissionAttempt::UserFull
                | AdmissionAttempt::AgentFull => {}
            }
        }

        // Enqueue and wait. NAN-3299 / NAN-4664: an overflow (global or
        // principal) waits here in a bounded fair queue for at most the
        // request's wait budget; it is refused only when that budget ends or
        // the queue is full.
        let (tx, rx) = oneshot::channel();
        let config = self.config.lock().await;
        let wait = effective_wait(current_wait_budget(), config.queue_timeout_ms);
        let max_queue_depth = config.max_queue_depth;
        let per_user_limit = config.per_user_limit;
        drop(config);

        if wait.is_zero() {
            // The caller asked not to wait.
            counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_timeout")
                .increment(1);
            histogram!("nanosiem_search_queue_wait_seconds", "outcome" => "rejected").record(0.0);
            return Err(AdmissionError::QueueTimeout { timeout_ms: 0 });
        }

        let enqueued_at = Instant::now();
        let seq = {
            let mut queue = lock_queue(&self.queue);
            queue.purge_abandoned();
            let user_queued = queue
                .waiters
                .iter()
                .filter(|queued| queued.subject == subject)
                .count();
            let principal_limit = principal_queue_limit(per_user_limit, max_queue_depth);
            if user_queued >= principal_limit as usize {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "principal_queue_full")
                    .increment(1);
                return Err(AdmissionError::UserLimitExceeded {
                    limit: principal_limit,
                });
            }
            if queue.len() >= max_queue_depth as usize {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_full")
                    .increment(1);
                return Err(AdmissionError::QueueFull {
                    depth: max_queue_depth,
                });
            }
            // NAN-4703: agents never fill the queue either. Their waiters
            // stop at the agent share of the queue, so a human always finds
            // a free place in line.
            if class == QueryClass::Agent {
                if let Some(rejected_at) = agent_queue_rejection(&queue.waiters, max_queue_depth) {
                    counter!("nanosiem_search_jobs_rejected_total", "reason" => "agent_queue_full")
                        .increment(1);
                    return Err(AdmissionError::QueueFull { depth: rejected_at });
                }
            }
            let seq = queue.push(QueuedSearch {
                seq: 0,
                job_id: job_id.to_string(),
                subject,
                priority,
                lane,
                class,
                principal_tag: 0,
                tx,
            });
            counter!("nanosiem_search_jobs_queued_total").increment(1);
            gauge!("nanosiem_search_queue_depth").set(queue.len() as f64);
            seq
        };
        // Dropping this future (client gone) removes the waiter at once.
        let mut guard = QueuedGuard {
            queue: &self.queue,
            seq,
            armed: true,
        };
        // Close the check-then-enqueue race with a concurrently dropped
        // permit: even if its notification arrived before this queue insert,
        // the drain loop gets another chance to observe the waiter.
        self.slot_available.notify_one();

        // Wait for a slot within the budget.
        let outcome = tokio::time::timeout(wait, rx).await;
        let wait_secs = enqueued_at.elapsed().as_secs_f64();
        match outcome {
            Ok(Ok(Ok(permit))) => {
                // We were admitted by drain_queue and receive the exact permit
                // whose local/distributed leases it took.
                guard.armed = false;
                histogram!("nanosiem_search_queue_wait_seconds", "outcome" => "admitted")
                    .record(wait_secs);
                counter!("nanosiem_search_jobs_admitted_total", "priority" => priority.to_string())
                    .increment(1);
                self.update_gauges().await;
                Ok(permit)
            }
            Ok(Ok(Err(e))) => {
                guard.armed = false;
                histogram!("nanosiem_search_queue_wait_seconds", "outcome" => "rejected")
                    .record(wait_secs);
                Err(e)
            }
            Ok(Err(_)) => {
                // Sender dropped (cancelled)
                drop(guard);
                histogram!("nanosiem_search_queue_wait_seconds", "outcome" => "cancelled")
                    .record(wait_secs);
                self.update_gauges().await;
                Err(AdmissionError::Cancelled)
            }
            Err(_) => {
                // The wait budget ended first.
                lock_queue(&self.queue).take(seq);
                guard.armed = false;
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "queue_timeout")
                    .increment(1);
                histogram!("nanosiem_search_queue_wait_seconds", "outcome" => "rejected")
                    .record(wait_secs);
                self.update_gauges().await;
                Err(AdmissionError::QueueTimeout {
                    timeout_ms: wait.as_millis() as u64,
                })
            }
        }
    }

    fn admitted_permit(
        &self,
        ledger: &mut LocalLedger,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        class: QueryClass,
        lease: std::time::Duration,
        redis: Option<RedisLease>,
    ) -> AdmissionPermit {
        let lease_id = ledger.insert(subject, lane, class, Instant::now() + lease);
        let renewer = spawn_lease_renewer(
            self.ledger.clone(),
            lease_id,
            lease,
            redis.as_ref().map(|lease| {
                (lease.conn.clone(), redis_permit_keys(subject, class), lease.permit_id.clone())
            }),
        );
        AdmissionPermit {
            subject,
            class,
            local_lease: Some(lease_id),
            ledger: self.ledger.clone(),
            slot_available: self.slot_available.clone(),
            redis,
            renewer,
        }
    }

    /// Try to admit immediately without queueing.
    async fn try_admit(
        &self,
        subject: AdmissionSubject,
        priority: QueryPriority,
        lane: AdmissionLane,
        class: QueryClass,
    ) -> Result<AdmissionAttempt, AdmissionError> {
        let config = self.config.lock().await;
        let global_limit = config.global_adhoc_limit;
        let user_limit = config.per_user_limit;
        drop(config);
        let lease = self.lease_for(priority);
        let auxiliary_limit = match lane {
            AdmissionLane::Primary => None,
            AdmissionLane::Auxiliary => Some(auxiliary_user_limit(user_limit)),
        };
        // NAN-4703: agents share the process's slots less the human reserve.
        let agent_limit = (class == QueryClass::Agent).then(|| agent_class_limit(global_limit));

        // Try Redis first if available
        let mut degraded = false;
        let redis_conn = self.redis_conn.lock().await.clone();
        if let Some(mut conn) = redis_conn {
            let keys = redis_permit_keys(subject, class);
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
                .arg(REDIS_ADMISSION_KEY_TTL_SECS)
                .arg(agent_limit.map_or(-1, i64::from));
            let result: Result<i64, _> = command.query_async(&mut conn).await;
            if matches!(result, Ok(1 | -1 | -2 | -4)) {
                self.redis_answered();
            }

            match result {
                Ok(1) => {
                    // Admitted via Redis — also lease locally for gauges.
                    let mut ledger = lock_ledger(&self.ledger);
                    ledger.reclaim_expired(Instant::now());
                    let permit = self.admitted_permit(
                        &mut ledger,
                        subject,
                        lane,
                        class,
                        lease,
                        Some(RedisLease { conn, permit_id }),
                    );
                    return Ok(AdmissionAttempt::Admitted(permit));
                }
                Ok(-2) => return Ok(AdmissionAttempt::UserFull),
                Ok(-4) if agent_limit.is_some() => return Ok(AdmissionAttempt::AgentFull),
                Ok(-1) => return Ok(AdmissionAttempt::GlobalFull),
                Ok(v) => {
                    if class == QueryClass::Agent {
                        tracing::error!(
                            value = v,
                            "Redis admission returned an invalid response; agent-class search fails closed"
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
                    // NAN-4703: an agent-class search fails closed. The local
                    // fallback counts only this replica, so it could not hold
                    // the human reserve; humans keep the fallback.
                    if class == QueryClass::Agent {
                        tracing::error!(
                            error = %e,
                            "Redis admission failed; agent-class search fails closed"
                        );
                        return Err(AdmissionError::Unavailable);
                    }
                    tracing::warn!("Redis admission check failed, falling back to local: {}", e);
                    // Fall through to local admission
                }
            }
            degraded = true;
        } else if self
            .redis_expected
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            if class == QueryClass::Agent {
                tracing::warn!(
                    "Redis admission is configured but not connected; agent-class search fails closed"
                );
                return Err(AdmissionError::Unavailable);
            }
            degraded = true;
        }

        // Fallback: local ledger. Single-instance (no Redis configured) keeps
        // the full global limit; a configured-but-failing Redis gets this
        // replica's share for a short grace, then fails closed.
        let local_global = if degraded {
            match self.redis_outage_limit(global_limit) {
                Some(limit) => limit,
                None => {
                    tracing::error!(
                        "Redis admission has been unavailable past its grace; ad-hoc search fails closed"
                    );
                    return Err(AdmissionError::Unavailable);
                }
            }
        } else {
            global_limit
        };
        Ok(self.try_admit_local(
            subject,
            lane,
            class,
            lease,
            local_global,
            user_limit,
            auxiliary_limit,
            agent_limit,
        ))
    }

    /// Local-only admission check (no Redis)
    #[allow(clippy::too_many_arguments)]
    fn try_admit_local(
        &self,
        subject: AdmissionSubject,
        lane: AdmissionLane,
        class: QueryClass,
        lease: std::time::Duration,
        global_limit: u32,
        user_limit: u32,
        auxiliary_limit: Option<u32>,
        agent_limit: Option<u32>,
    ) -> AdmissionAttempt {
        let mut ledger = lock_ledger(&self.ledger);
        ledger.reclaim_expired(Instant::now());

        if ledger.user_count(&subject) >= user_limit {
            return AdmissionAttempt::UserFull;
        }
        if auxiliary_limit.is_some_and(|limit| ledger.user_auxiliary_count(&subject) >= limit) {
            return AdmissionAttempt::UserFull;
        }
        if agent_limit.is_some_and(|limit| ledger.agent_count() >= limit) {
            return AdmissionAttempt::AgentFull;
        }
        if ledger.active() >= global_limit {
            return AdmissionAttempt::GlobalFull;
        }

        AdmissionAttempt::Admitted(self.admitted_permit(
            &mut ledger,
            subject,
            lane,
            class,
            lease,
            None,
        ))
    }

    /// NAN-4928 review P1: the global limit a local fallback may use while
    /// configured Redis admission is failing. The local ledger counts only
    /// this replica, so a full fallback would multiply the global limit by
    /// the replica count exactly when ClickHouse coordination is degraded.
    /// Within the grace each replica keeps `global / replicas` (at least one);
    /// after it, ad-hoc searches fail closed (`Unavailable`, a retryable 429)
    /// until Redis answers again.
    fn redis_outage_limit(&self, global_limit: u32) -> Option<u32> {
        let mut since = self
            .redis_failing_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started = *since.get_or_insert_with(Instant::now);
        if started.elapsed() > self.redis_outage_grace {
            counter!("nanosiem_search_admission_redis_outage_refusals_total").increment(1);
            None
        } else {
            Some((global_limit / self.replica_count.max(1)).max(1))
        }
    }

    fn redis_answered(&self) {
        if let Ok(mut since) = self.redis_failing_since.lock() {
            *since = None;
        }
    }

    fn local_active(&self) -> u32 {
        lock_ledger(&self.ledger).active()
    }

    /// Update Prometheus gauges for queue depth and active queries
    async fn update_gauges(&self) {
        let queued = lock_queue(&self.queue).len() as f64;
        let active = self.local_active() as f64;
        gauge!("nanosiem_search_queue_depth").set(queued);
        gauge!("nanosiem_search_active_queries").set(active);
    }

    /// Cancel a queued search by job_id (before it starts executing)
    pub async fn cancel_queued(&self, job_id: &str) {
        self.remove_from_queue(job_id).await;
    }

    /// Get 1-based queue position for a job, in service order.
    pub async fn queue_position(&self, job_id: &str) -> Option<u32> {
        let mut queue = lock_queue(&self.queue);
        let order = service_order(&mut queue.waiters);
        order
            .into_iter()
            .position(|index| queue.waiters[index].job_id == job_id)
            .map(|pos| (pos + 1) as u32)
    }

    /// Get total queue depth
    pub async fn queue_depth(&self) -> u32 {
        let mut queue = lock_queue(&self.queue);
        queue.purge_abandoned();
        queue.len() as u32
    }

    /// Get admission statistics
    pub async fn stats(&self) -> AdmissionStats {
        let queued = {
            let mut queue = lock_queue(&self.queue);
            queue.purge_abandoned();
            queue.len() as u32
        };
        let ledger = lock_ledger(&self.ledger);
        AdmissionStats {
            active_adhoc: ledger.active(),
            queued,
            per_user_counts: ledger
                .per_user
                .iter()
                .map(|(subject, count)| (subject.to_string(), *count))
                .collect(),
        }
    }

    /// The process-wide concurrency used to divide gathered-result memory.
    pub async fn global_adhoc_limit(&self) -> u32 {
        self.config.lock().await.global_adhoc_limit
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
                        if lock_queue(&controller.queue).is_empty() {
                            continue;
                        }
                    }
                }
                controller.drain_queue().await;
            }
        });
    }

    /// Try to admit queued searches when slots become available, in
    /// [`service_order`].
    async fn drain_queue(&self) {
        // Try each request present at the start at most once, in service
        // order. Principal- and class-full work is skipped (it stays queued);
        // a global-full result stops the pass because no queued request can
        // admit then.
        //
        // A waiter stays in the queue while it is tried and leaves it only
        // once admitted, so during the pass (which awaits Redis) it is still
        // visible: a cancel reaches it, its queue position holds, the queue
        // bounds and tags count it, and a releasing caller cannot see an
        // empty queue and barge past it (NAN-4664 review).
        let order: Vec<u64> = {
            let mut queue = lock_queue(&self.queue);
            queue.purge_abandoned();
            service_order(&mut queue.waiters)
                .into_iter()
                .map(|index| queue.waiters[index].seq)
                .collect()
        };
        for seq in order {
            // Never hold the queue lock while awaiting Redis. Apart from
            // keeping cancellation responsive, this lets a dropping permit
            // wake another drain without deadlocking behind an I/O attempt.
            let candidate = {
                let mut queue = lock_queue(&self.queue);
                match queue.waiters.iter().find(|queued| queued.seq == seq) {
                    // Cancelled, timed out or its client left meanwhile.
                    None => None,
                    Some(queued) if queued.tx.is_closed() => {
                        // NAN-4664: the caller is gone; never start its work.
                        queue.take(seq);
                        None
                    }
                    Some(queued) => {
                        Some((queued.subject, queued.priority, queued.lane, queued.class))
                    }
                }
            };
            let Some((subject, priority, lane, class)) = candidate else {
                continue;
            };

            match self.try_admit(subject, priority, lane, class).await {
                Ok(AdmissionAttempt::Admitted(permit)) => {
                    let queued = {
                        let mut queue = lock_queue(&self.queue);
                        let queued = queue.take(seq);
                        if let Some(queued) = &queued {
                            queue.record_admitted(queued);
                        }
                        queued
                    };
                    match queued {
                        // NAN-4915: a receiver that left in the meantime gets
                        // nothing: the permit drops, so no lease leaks and no
                        // work starts.
                        Some(queued) => {
                            if queued.tx.send(Ok(permit)).is_err() {
                                counter!("nanosiem_search_admission_rollbacks_total")
                                    .increment(1);
                            }
                        }
                        // Cancelled, timed out or gone while it was tried.
                        None => {
                            counter!("nanosiem_search_admission_rollbacks_total").increment(1);
                            drop(permit)
                        }
                    }
                }
                Ok(AdmissionAttempt::GlobalFull) => {
                    // The process ceiling is still full; every waiter keeps
                    // its seq and tag, so its place in line too.
                    break;
                }
                Ok(AdmissionAttempt::UserFull | AdmissionAttempt::AgentFull) => {
                    // Do not let a saturated principal or agent class first in
                    // line block other waiters from a free slot (humans are
                    // served past capped agents, NAN-4703); it stays queued.
                }
                Err(error) => {
                    // An admission outage is terminal for this waiter, but
                    // must not stall unrelated work behind it.
                    let queued = lock_queue(&self.queue).take(seq);
                    if let Some(queued) = queued {
                        let _ = queued.tx.send(Err(error));
                    }
                }
            }
        }

        let depth = {
            let mut queue = lock_queue(&self.queue);
            queue.prune_clocks();
            queue.len()
        };
        gauge!("nanosiem_search_queue_depth").set(depth as f64);
        gauge!("nanosiem_search_active_queries").set(self.local_active() as f64);
    }

    /// Remove a job from the queue
    async fn remove_from_queue(&self, job_id: &str) {
        let mut queue = lock_queue(&self.queue);
        let mut kept = Vec::with_capacity(queue.waiters.len());
        for queued in std::mem::take(&mut queue.waiters) {
            if queued.job_id == job_id {
                let _ = queued.tx.send(Err(AdmissionError::Cancelled));
            } else {
                kept.push(queued);
            }
        }
        queue.waiters = kept;
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "admission_cancellation_tests.rs"]
mod cancellation_tests;
