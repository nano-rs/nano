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
//!
//! **Queue, not reject (NAN-4664).** Overflow waits in a bounded fair queue
//! for at most the request's wait budget ([`ADMISSION_WAIT_HEADER`], default
//! [`DEFAULT_ADMISSION_WAIT`], capped at `queue_timeout_ms`); a refusal
//! (`QueueTimeout`, `QueueFull`, 429 with `Retry-After`) comes only when that
//! budget ends or the queue is full. Concurrency limits are unchanged. The
//! drain serves waiters in [`service_order`]: round-robin across principals
//! within a tenant, round-robin across tenants, priority only inside a
//! tenant. A caller that disconnects leaves the queue at once and its work is
//! never started.
//!
//! **Pooled cells.** One search process fronts every tenant of a pooled lake
//! cell. Tenants share only `global_adhoc_limit` (the cell ceiling) and the
//! process queue bound; each shared tenant also has its own concurrency cap
//! (`shared_tenant_adhoc_limit`), its own queue quota and reserved waiters
//! (NAN-3286), so one tenant's backlog, priority or full queue never refuses
//! or reorders another tenant's searches. Below this, each tenant's query[T]
//! process on the cell has its own native-work slots (a FIFO with a 20 s
//! deadline, whose overflow the handler escalates to a durable job), and the
//! cell's cgroups divide CPU between tenants by weight; no queue is shared
//! across tenants there.

use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// NAN-3299 / NAN-4664: waiters one principal (a user or an API key) may
/// queue beyond their running searches. A per-principal overflow waits
/// instead of failing; the bound only keeps one principal from filling its
/// tenant's (or a dedicated process's) whole queue, so other principals can
/// still enqueue. `queue_share` is the bound of the queue the principal waits
/// in: `max_queue_depth` (dedicated) or its tenant's quota (shared).
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
    /// An automated agent's leftover cell query (agent scans belong on the
    /// agent lane, not the cell): a hard cap ([`agent_class_limit`]) so it
    /// never takes the share reserved for humans, and the lowest priority
    /// in its tenant's queue. No extra budget: deadlines and result caps
    /// are the human ones.
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

/// Whether an API key (dedicated) or tenant automation key (shared) is an
/// agent's credential, from its server-stored name.
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

/// Slots of an admission scope (a shared tenant's limit, or a dedicated
/// process's ceiling) that agent-class searches never take: a quarter, at
/// least one. A scope of one slot cannot reserve any.
pub const fn human_reserved_slots(scope_limit: u32) -> u32 {
    if scope_limit <= 1 {
        return 0;
    }
    let quarter = scope_limit / 4;
    if quarter == 0 { 1 } else { quarter }
}

/// The most permits agent-class searches of one admission scope hold at
/// once: the scope's limit less [`human_reserved_slots`] (at least one).
pub const fn agent_class_limit(scope_limit: u32) -> u32 {
    let limit = scope_limit.saturating_sub(human_reserved_slots(scope_limit));
    if limit == 0 { 1 } else { limit }
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
    ADMISSION_QUERY_CLASS.try_with(|class| *class).unwrap_or_default()
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
/// interactive escalation deadline (45 s), so a browser search that waits
/// becomes the durable job the UI follows instead of a 429, and well above a
/// fleet's expected wait (16 closed-loop agents over 5 permits at the
/// bakeoff's 3.5 s p50 queue for ~8 s each).
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
    ADMISSION_WAIT_BUDGET.scope(std::time::Duration::MAX, future).await
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
    per_tenant: HashMap<uuid::Uuid, u32>,
    per_user: HashMap<AdmissionSubject, u32>,
    per_user_auxiliary: HashMap<AdmissionSubject, u32>,
    /// NAN-4703: agent-class permits. `None` counts every agent permit of
    /// the process (the cell-wide agent cap; for a dedicated process it is
    /// also its scope), `Some(tenant)` a shared tenant's agent permits.
    per_scope_agent: HashMap<Option<uuid::Uuid>, u32>,
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

    fn agent_count(&self, tenant_id: &Option<uuid::Uuid>) -> u32 {
        self.per_scope_agent.get(tenant_id).copied().unwrap_or(0)
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
            increment(&mut self.per_scope_agent, None);
            if subject.tenant_id.is_some() {
                increment(&mut self.per_scope_agent, subject.tenant_id);
            }
        }
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
        if lease.class == QueryClass::Agent {
            decrement(&mut self.per_scope_agent, &None);
            if lease.subject.tenant_id.is_some() {
                decrement(&mut self.per_scope_agent, &lease.subject.tenant_id);
            }
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

    #[cfg(test)]
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

/// NAN-4703: the agent-class permits of one admission scope (`None`: every
/// agent permit of the cell, which is a dedicated process's scope too).
fn redis_agent_key(tenant_id: Option<uuid::Uuid>) -> String {
    match tenant_id {
        Some(tenant_id) => format!("search:admission:v2:tenant:{tenant_id}:agent"),
        None => "search:admission:v2:agent".to_string(),
    }
}

/// Every key one permit is recorded in, in the order `ACQUIRE_LUA` expects:
/// cell, user, user-auxiliary, the tenant key for shared subjects, then for
/// an agent-class permit the cell-wide agent key and, for a shared subject,
/// its tenant's agent key.
fn redis_permit_keys(subject: AdmissionSubject, class: QueryClass) -> Vec<String> {
    let mut keys = vec![
        REDIS_GLOBAL_KEY.to_string(),
        redis_user_key(subject),
        redis_user_auxiliary_key(subject),
    ];
    if let Some(tenant_id) = subject.tenant_id {
        keys.push(redis_tenant_key(tenant_id));
    }
    if class == QueryClass::Agent {
        keys.push(redis_agent_key(None));
        if subject.tenant_id.is_some() {
            keys.push(redis_agent_key(subject.tenant_id));
        }
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
/// then KEYS[4] = tenant (enterprise-shared only), then for the agent class
/// (NAN-4703) the cell-wide agent key and, with a tenant key, the tenant's
/// agent key
/// ARGV[1] = now (Unix ms), ARGV[2] = lease expiry (Unix ms), ARGV[3] = permit id,
/// ARGV[4] = cell limit, ARGV[5] = user limit,
/// ARGV[6] = auxiliary user limit, or -1 for a primary request,
/// ARGV[7] = tenant limit (ignored without a tenant key), ARGV[8] = key TTL seconds,
/// ARGV[9] = 1 with a tenant key, else 0,
/// ARGV[10] = cell-wide agent-class limit, or -1 for a human-class request,
/// ARGV[11] = the tenant's agent-class limit, or -1 (human class or no tenant)
///
/// Returns 1 admitted, -1 cell full, -2 user full, -3 tenant full, -4 the
/// cell's or the tenant's agent class full. Every "full" answer is queueable; expired
/// leases are pruned before counting.
const ACQUIRE_LUA: &str = r#"
local now = tonumber(ARGV[1])
local expires = tonumber(ARGV[2])
local permit = ARGV[3]
local cell_limit = tonumber(ARGV[4])
local user_limit = tonumber(ARGV[5])
local auxiliary_limit = tonumber(ARGV[6])
local tenant_limit = tonumber(ARGV[7])
local key_ttl = tonumber(ARGV[8])
local has_tenant = ARGV[9] == '1'
local agent_cell_limit = tonumber(ARGV[10])
local agent_tenant_limit = tonumber(ARGV[11])
local next_key = 4
if has_tenant then
    next_key = 5
end
local agent_cell_key = nil
local agent_tenant_key = nil
if agent_cell_limit >= 0 then
    agent_cell_key = KEYS[next_key]
    if has_tenant and agent_tenant_limit >= 0 then
        agent_tenant_key = KEYS[next_key + 1]
    end
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
if has_tenant and redis.call('ZCARD', KEYS[4]) >= tenant_limit then
    return -3
end
if agent_tenant_key and redis.call('ZCARD', agent_tenant_key) >= agent_tenant_limit then
    return -4
end
if agent_cell_key and redis.call('ZCARD', agent_cell_key) >= agent_cell_limit then
    return -4
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
if agent_cell_key then
    lease(agent_cell_key)
end
if agent_tenant_key then
    lease(agent_tenant_key)
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

/// NAN-4703: an agent-class permit's caps: the cell-wide agent cap, and a
/// shared tenant's own.
#[derive(Debug, Clone, Copy)]
struct AgentLimits {
    cell: u32,
    tenant: Option<u32>,
}

enum AdmissionAttempt {
    Admitted(AdmissionPermit),
    CellFull,
    TenantFull,
    UserFull,
    /// NAN-4703: the cell's or the tenant's agent class is at its cap
    /// (humans may still admit).
    AgentFull,
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
    class: QueryClass,
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
            let class = self.class;
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

/// NAN-4703: whether a new agent-class waiter is refused, and at which depth.
/// Agent waiters of one scope stop at [`agent_class_limit`] of its queue
/// share (`queue_share`), and all agent waiters at that of the process
/// queue, so agents never take the places in line kept for humans.
fn agent_queue_rejection(
    waiters: &[QueuedSearch],
    subject: AdmissionSubject,
    queue_share: u32,
    max_queue_depth: u32,
) -> Option<u32> {
    let agents = waiters.iter().filter(|queued| queued.class == QueryClass::Agent);
    let scope_agents = agents
        .clone()
        .filter(|queued| queued.subject.tenant_id == subject.tenant_id)
        .count();
    let scope_limit = agent_class_limit(queue_share);
    if scope_agents >= scope_limit as usize {
        return Some(scope_limit);
    }
    let process_limit = agent_class_limit(max_queue_depth);
    (agents.count() >= process_limit as usize).then_some(process_limit)
}

/// A queued search waiting for admission
struct QueuedSearch {
    /// Unique, monotonically increasing per controller: FIFO order and the
    /// handle a waiter's [`QueuedGuard`] removes itself by.
    seq: u64,
    job_id: String,
    subject: AdmissionSubject,
    require_distributed: bool,
    priority: QueryPriority,
    lane: AdmissionLane,
    class: QueryClass,
    /// Fair-queue tag among the tenant's principals (see [`WaitQueue`]).
    principal_tag: u64,
    /// Fair-queue tag among tenants (see [`WaitQueue`]).
    tenant_tag: u64,
    /// Sender to notify when admitted
    tx: oneshot::Sender<Result<AdmissionPermit, AdmissionError>>,
}

/// NAN-4664: the bounded admission queue, served by start-time fair
/// queueing at two levels.
///
/// Every waiter carries two tags, taken at enqueue: a **principal tag**
/// (one past the later of its tenant's virtual clock and its principal's
/// newest queued tag) and a **tenant tag** (the same across tenants). A
/// virtual clock advances to the tags of each admitted waiter, so a
/// principal or tenant arriving late starts level with the others' next
/// turn instead of behind their whole backlog, and one that was just served
/// goes to the back. The drain serves:
///
/// 1. **Across tenants**: the lowest tenant tag first (ties FIFO), i.e.
///    round-robin between tenants with waiters (NAN-3286). Priority never
///    crosses a tenant: another tenant's Interactive backlog cannot jump this
///    tenant's turn. Dedicated deployments are one tenant (`tenant_id: None`).
/// 2. **Within the tenant whose turn it is**: higher priority first, then
///    primary before auxiliary (NAN-3299), then the lowest principal tag
///    (round-robin across principals: one agent with a deep backlog cannot
///    starve the tenant's other agents or analysts), then FIFO.
///
/// Tags are tickets of their flow, not of one search: [`service_order`]
/// hands a flow's tickets to its waiters in the flow's own order, so a
/// principal's Interactive search can use the ticket its older Analytics
/// search took. Memory is bounded by `max_queue_depth` (and the per-tenant
/// quotas) whatever the arrival rate; the per-tenant clocks exist only while
/// a tenant has waiters.
#[derive(Default)]
struct WaitQueue {
    next_seq: u64,
    waiters: Vec<QueuedSearch>,
    /// Tenant tag of the latest admission across tenants.
    tenant_clock: u64,
    /// Principal tag of the latest admission, per tenant with waiters.
    principal_clocks: HashMap<Option<uuid::Uuid>, u64>,
}

impl WaitQueue {
    fn len(&self) -> usize {
        self.waiters.len()
    }

    fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    /// Enqueue `search` (its `seq` and tags are assigned here); returns its seq.
    fn push(&mut self, mut search: QueuedSearch) -> u64 {
        self.next_seq += 1;
        search.seq = self.next_seq;
        let tenant = search.subject.tenant_id;
        let principal_clock = self.principal_clocks.get(&tenant).copied().unwrap_or(0);
        let principal_last = self
            .waiters
            .iter()
            .filter(|queued| queued.subject == search.subject)
            .map(|queued| queued.principal_tag)
            .max()
            .unwrap_or(0);
        let tenant_last = self
            .waiters
            .iter()
            .filter(|queued| queued.subject.tenant_id == tenant)
            .map(|queued| queued.tenant_tag)
            .max()
            .unwrap_or(0);
        search.principal_tag = principal_clock.max(principal_last) + 1;
        search.tenant_tag = self.tenant_clock.max(tenant_last) + 1;
        self.waiters.push(search);
        self.next_seq
    }

    /// Advance the virtual clocks past an admitted waiter's tags.
    fn record_admitted(&mut self, search: &QueuedSearch) {
        self.tenant_clock = self.tenant_clock.max(search.tenant_tag);
        let clock = self.principal_clocks.entry(search.subject.tenant_id).or_insert(0);
        *clock = (*clock).max(search.principal_tag);
    }

    /// Forget the clocks of tenants with no waiters (bounded state).
    fn prune_clocks(&mut self) {
        let waiters = &self.waiters;
        self.principal_clocks
            .retain(|tenant, _| waiters.iter().any(|queued| queued.subject.tenant_id == *tenant));
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

/// Hand each flow's tags to its waiters in the flow's own order, so tickets
/// follow service order rather than arrival.
fn reassign_tags<K: std::hash::Hash + Eq>(
    queue: &mut [QueuedSearch],
    flow: impl Fn(&QueuedSearch) -> K,
    order_key: impl Fn(&QueuedSearch) -> (u8, u8, u64, u64),
    tag: fn(&mut QueuedSearch) -> &mut u64,
) {
    let mut flows: HashMap<K, Vec<usize>> = HashMap::new();
    for (index, queued) in queue.iter().enumerate() {
        flows.entry(flow(queued)).or_default().push(index);
    }
    for mut indices in flows.into_values() {
        let mut tags: Vec<u64> = indices.iter().map(|&index| *tag(&mut queue[index])).collect();
        tags.sort_unstable();
        indices.sort_by_key(|&index| order_key(&queue[index]));
        for (index, value) in indices.into_iter().zip(tags) {
            *tag(&mut queue[index]) = value;
        }
    }
}

/// A waiter's rank inside its tenant's turn: every human-class search
/// before any agent-class one (NAN-4703: agents are the lowest priority),
/// then by priority.
fn queue_rank(queued: &QueuedSearch) -> u8 {
    let class = match queued.class {
        QueryClass::Human => 0,
        QueryClass::Agent => 1,
    };
    class * 16 + queued.priority.ordinal()
}

/// The waiters' service order, as indices into `queue`, first served first
/// (see [`WaitQueue`]). Normalizes the tags in place. The queue is bounded
/// (a few hundred entries at most), so this runs on every drain.
fn service_order(queue: &mut [QueuedSearch]) -> Vec<usize> {
    reassign_tags(
        queue,
        |queued| queued.subject,
        |queued| (queue_rank(queued), queued.lane.ordinal(), queued.seq, 0),
        |queued| &mut queued.principal_tag,
    );
    reassign_tags(
        queue,
        |queued| queued.subject.tenant_id,
        |queued| (queue_rank(queued), queued.lane.ordinal(), queued.principal_tag, queued.seq),
        |queued| &mut queued.tenant_tag,
    );
    let mut order: Vec<usize> = (0..queue.len()).collect();
    order.sort_by_key(|&index| (queue[index].tenant_tag, queue[index].seq));
    order
}

fn lock_queue(queue: &std::sync::Mutex<WaitQueue>) -> std::sync::MutexGuard<'_, WaitQueue> {
    queue.lock().unwrap_or_else(|poisoned| {
        tracing::error!("search admission queue was poisoned; repairing");
        poisoned.into_inner()
    })
}

/// NAN-4664: removes a waiter from the queue when its `acquire` future is
/// dropped (client disconnect, deadline escalation, task abort) so a dead
/// waiter never holds a queue slot and is never admitted.
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
    queue: std::sync::Mutex<WaitQueue>,
    /// NAN-3286: `NANO_SEARCH_SHARED_TENANT_QUEUE_LIMIT`, read once.
    shared_tenant_queue_limit_override: Option<u32>,
    /// Test hook: a fixed lease instead of the per-priority one.
    lease_override: Option<std::time::Duration>,
    slot_available: Arc<Notify>,
    // Optional Redis connection for cluster-wide counters
    redis_conn: Mutex<Option<crate::redis_transport::ReconnectingConnection>>,
    /// NAN-4703: the deployment configured Redis admission (`REDIS_URL`),
    /// even if the connection failed at boot. Agent-class searches then
    /// never take the per-replica local fallback.
    redis_expected: std::sync::atomic::AtomicBool,
}

impl AdmissionController {
    /// Create a new admission controller with the given configuration
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config: Mutex::new(config),
            ledger: Arc::new(std::sync::Mutex::new(LocalLedger::default())),
            queue: std::sync::Mutex::new(WaitQueue::default()),
            shared_tenant_queue_limit_override: std::env::var(SHARED_TENANT_QUEUE_LIMIT_ENV)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok()),
            lease_override: None,
            slot_available: Arc::new(Notify::new()),
            redis_conn: Mutex::new(None),
            redis_expected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// NAN-4703: record that this deployment configured Redis admission.
    /// Without a working connection, agent-class searches fail closed
    /// instead of counting against this replica's local ledger only
    /// (humans keep the local fallback).
    pub fn expect_redis(&self) {
        self.redis_expected.store(true, std::sync::atomic::Ordering::Relaxed);
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

    #[tracing::instrument(name = "search.admission.wait", skip_all)]
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
                class: QueryClass::Human,
                local_lease: None,
                ledger: self.ledger.clone(),
                slot_available: self.slot_available.clone(),
                redis: None,
            });
        }

        // Try immediate admission, but never barge past waiters: with anyone
        // queued, a new arrival takes its turn through the fair drain. In a
        // closed-loop fleet an agent re-acquires the instant it releases, so
        // barging let it re-take its own freed slot ahead of every waiter
        // (NAN-4664). The drain still admits it at once when the waiters
        // ahead are blocked on their own tenant or principal caps.
        let class = current_query_class();
        let (queue_idle, human_waiting) = {
            let mut queue = lock_queue(&self.queue);
            queue.purge_abandoned();
            let human_waiting = queue.waiters.iter().any(|queued| queued.class == QueryClass::Human);
            (queue.is_empty(), human_waiting)
        };
        // A fail-fast caller (budget 0) never waits, so it only ever takes a
        // slot that is free right now. NAN-4703: a fail-fast agent never
        // takes it past a waiting human (agents are the lowest priority).
        let fail_fast = current_wait_budget().is_some_and(|budget| budget.is_zero());
        if queue_idle || (fail_fast && !(class == QueryClass::Agent && human_waiting)) {
            match self
                .try_admit(subject, require_distributed, priority, lane, class)
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
                | AdmissionAttempt::UserFull
                | AdmissionAttempt::AgentFull => {}
            }
        }

        // Enqueue and wait. NAN-3299 / NAN-4664: an overflow (cell, tenant
        // or principal) waits here in a bounded fair queue for at most the
        // request's wait budget; it is refused only when that budget ends or
        // the queue it waits in is full.
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
            let tenant_queued = queue
                .waiters
                .iter()
                .filter(|queued| queued.subject.tenant_id == subject.tenant_id)
                .count();
            let user_queued = queue
                .waiters
                .iter()
                .filter(|queued| queued.subject == subject)
                .count();
            let queue_share = if subject.tenant_id.is_some() {
                shared_tenant_queue_limit(max_queue_depth, self.shared_tenant_queue_limit_override)
            } else {
                max_queue_depth
            };
            let principal_limit = principal_queue_limit(per_user_limit, queue_share);
            if user_queued >= principal_limit as usize {
                counter!("nanosiem_search_jobs_rejected_total", "reason" => "principal_queue_full")
                    .increment(1);
                return Err(AdmissionError::UserLimitExceeded {
                    limit: principal_limit,
                });
            }
            // NAN-3286: one tenant's waiters are bounded by its own share, so
            // a tenant saturating the process queue cannot turn another
            // tenant's searches into immediate `QueueFull`.
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
            // NAN-4703: agents never fill the queue either. Their waiters
            // stop at the agent share of the tenant's queue and of the
            // process queue, so a human always finds a free place in line.
            if class == QueryClass::Agent {
                if let Some(rejected_at) = agent_queue_rejection(&queue.waiters, subject, queue_share, max_queue_depth) {
                    counter!("nanosiem_search_jobs_rejected_total", "reason" => "agent_queue_full")
                        .increment(1);
                    return Err(AdmissionError::QueueFull { depth: rejected_at });
                }
            }
            let seq = queue.push(QueuedSearch {
                seq: 0,
                job_id: job_id.to_string(),
                subject,
                require_distributed,
                priority,
                lane,
                class,
                principal_tag: 0,
                tenant_tag: 0,
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
        AdmissionPermit {
            subject,
            class,
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
        class: QueryClass,
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
        // NAN-4703: agents share the cell's slots, and a shared tenant's,
        // less the human reserve of each.
        let agent_limit = (class == QueryClass::Agent).then(|| AgentLimits {
            cell: agent_class_limit(global_limit),
            tenant: subject.tenant_id.map(|_| agent_class_limit(tenant_limit)),
        });

        // Try Redis first if available
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
                .arg(tenant_limit)
                .arg(REDIS_ADMISSION_KEY_TTL_SECS)
                .arg(i64::from(subject.tenant_id.is_some()))
                .arg(agent_limit.map_or(-1, |limits| i64::from(limits.cell)))
                .arg(agent_limit.and_then(|limits| limits.tenant).map_or(-1, i64::from));
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
                        class,
                        lease,
                        Some(RedisLease { conn, permit_id }),
                    );
                    return Ok(AdmissionAttempt::Admitted(permit));
                }
                Ok(-2) => return Ok(AdmissionAttempt::UserFull),
                Ok(-4) if agent_limit.is_some() => return Ok(AdmissionAttempt::AgentFull),
                Ok(-1) => return Ok(AdmissionAttempt::CellFull),
                Ok(-3) if subject.tenant_id.is_some() => {
                    // This tenant is full, but another tenant may still use a
                    // free cell slot. The queue drain skips this tenant until
                    // one of its permits releases.
                    return Ok(AdmissionAttempt::TenantFull);
                }
                Ok(v) => {
                    if require_distributed || class == QueryClass::Agent {
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
                    // NAN-4703: an agent-class search fails closed too. The
                    // local fallback counts only this replica, so it could not
                    // hold the cell's human reserve; humans keep the fallback.
                    if require_distributed || class == QueryClass::Agent {
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
        if class == QueryClass::Agent && self.redis_expected.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                tenant_id = ?subject.tenant_id,
                "Redis admission is configured but not connected; agent-class search fails closed"
            );
            return Err(AdmissionError::Unavailable);
        }

        // Fallback: local ledger (single-instance or Redis unavailable)
        Ok(self.try_admit_local(
            subject,
            lane,
            class,
            lease,
            global_limit,
            tenant_limit,
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
        tenant_limit: u32,
        user_limit: u32,
        auxiliary_limit: Option<u32>,
        agent_limit: Option<AgentLimits>,
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
        if let Some(limits) = agent_limit {
            let tenant_full = subject.tenant_id.is_some()
                && limits.tenant.is_some_and(|limit| ledger.agent_count(&subject.tenant_id) >= limit);
            if tenant_full || ledger.agent_count(&None) >= limits.cell {
                return AdmissionAttempt::AgentFull;
            }
        }
        if ledger.active() >= global_limit {
            return AdmissionAttempt::CellFull;
        }

        AdmissionAttempt::Admitted(self.admitted_permit(&mut ledger, subject, lane, class, lease, None))
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
        let mut queue = lock_queue(&self.queue);
        // The tenant's own waiters in service order: a shared caller never
        // learns another tenant's backlog from its position.
        service_order(&mut queue.waiters)
            .into_iter()
            .map(|index| &queue.waiters[index])
            .filter(|queued| queued.subject.belongs_to(scope))
            .position(|queued| queued.job_id == job_id)
            .map(|pos| (pos + 1) as u32)
    }

    /// Get total queue depth
    pub async fn queue_depth(&self) -> u32 {
        lock_queue(&self.queue).len() as u32
    }

    /// Get admission statistics
    pub async fn stats(&self) -> AdmissionStats {
        let queued = lock_queue(&self.queue).len() as u32;
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

    /// The process-wide concurrency used to divide gathered-result memory.
    pub async fn global_adhoc_limit(&self) -> u32 {
        self.config.lock().await.global_adhoc_limit
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
        // order. Tenant- and principal-full work is skipped (it stays
        // queued); a cell-full result stops the pass because no queued
        // request can safely admit then.
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
                    Some(queued) => Some((
                        queued.subject,
                        queued.require_distributed,
                        queued.priority,
                        queued.lane,
                        queued.class,
                    )),
                }
            };
            let Some((subject, require_distributed, priority, lane, class)) = candidate else {
                continue;
            };

            match self
                .try_admit(subject, require_distributed, priority, lane, class)
                .await
            {
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
                        // A receiver that left in the meantime gets nothing:
                        // the permit drops, so no lease leaks and no work starts.
                        Some(queued) => {
                            let _ = queued.tx.send(Ok(permit));
                        }
                        // Cancelled, timed out or gone while it was tried.
                        None => drop(permit),
                    }
                }
                Ok(AdmissionAttempt::CellFull) => {
                    // The process/cell ceiling is still full; every waiter
                    // keeps its seq and tags, so its place in line too.
                    break;
                }
                Ok(
                    AdmissionAttempt::TenantFull
                    | AdmissionAttempt::UserFull
                    | AdmissionAttempt::AgentFull,
                ) => {
                    // Do not let a saturated tenant, principal or agent class
                    // first in line block other waiters from a free slot (a
                    // tenant's humans are served past its capped agents, its
                    // reserved share, NAN-4703); it stays queued.
                }
                Err(error) => {
                    // A shared admission outage is terminal for this waiter,
                    // but must not stall unrelated tenant/user work behind it.
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
    async fn remove_from_queue(&self, job_id: &str, scope: Option<SearchTenantScope>) {
        let mut queue = lock_queue(&self.queue);
        let mut kept = Vec::with_capacity(queue.waiters.len());
        for queued in std::mem::take(&mut queue.waiters) {
            let scope_matches = scope
                .map(|scope| queued.subject.belongs_to(scope))
                .unwrap_or(true);
            if queued.job_id == job_id && scope_matches {
                let _ = queued.tx.send(Err(AdmissionError::Cancelled));
            } else {
                kept.push(queued);
            }
        }
        queue.waiters = kept;
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
                Err(AdmissionError::UserLimitExceeded { limit: 8 }) => rejected += 1,
                Err(AdmissionError::QueueTimeout { .. }) => timed_out += 1,
                Err(other) => panic!("unexpected admission result: {other}"),
            }
        }
        // Two run (the cap is never raced past); the principal's queue share
        // (NAN-4664: half the tenant's quota of 16) waits and, with no
        // release, times out; only the overflow beyond that is refused.
        assert_eq!(permits.len(), 2);
        assert_eq!(timed_out, 8);
        assert_eq!(rejected, 22);
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
            redis_permit_keys(a, QueryClass::Human),
            vec![
                REDIS_GLOBAL_KEY.to_string(),
                redis_user_key(a),
                format!("{}:aux", redis_user_key(a)),
                redis_tenant_key(Uuid::from_u128(0xa)),
            ]
        );
        assert_eq!(
            redis_permit_keys(AdmissionSubject::new(SearchTenantScope::Dedicated, user), QueryClass::Human).len(),
            3
        );
        // NAN-4703: an agent-class permit is also recorded in the cell-wide
        // agent key and, for a shared tenant, its tenant's agent key, in
        // that order after the tenant key.
        let agent_keys = redis_permit_keys(a, QueryClass::Agent);
        assert_eq!(agent_keys.len(), 6);
        assert_eq!(agent_keys[4], "search:admission:v2:agent");
        assert_eq!(agent_keys[5], format!("search:admission:v2:tenant:{}:agent", Uuid::from_u128(0xa)));
        let dedicated_agent = redis_permit_keys(AdmissionSubject::new(SearchTenantScope::Dedicated, user), QueryClass::Agent);
        assert_eq!(dedicated_agent.len(), 4);
        assert_eq!(dedicated_agent[3], "search:admission:v2:agent");
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
        // NAN-4664: a principal may hold half its queue (dedicated: the
        // process queue), never less than twice its running permits.
        assert_eq!(principal_queue_limit(10, 25), 20);
        assert_eq!(principal_queue_limit(5, 100), 50);
        assert_eq!(principal_queue_limit(5, 4), 4);
        assert_eq!(principal_queue_limit(1, 0), 1);
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

    // ------------------------------------------------------------------
    // NAN-4664: bounded fair queue instead of rejection
    // ------------------------------------------------------------------

    fn fleet_config(global: u32, per_user: u32) -> AdmissionConfig {
        AdmissionConfig {
            global_adhoc_limit: global,
            shared_tenant_adhoc_limit: global,
            per_user_limit: per_user,
            max_queue_depth: 100,
            queue_timeout_ms: 300_000,
        }
    }

    /// The bakeoff shape: 16 closed-loop agents, each always with exactly one
    /// search in flight, 10 hunts each, over a cap of 5. Every hunt waits
    /// inside its budget instead of failing, and the cap is never exceeded.
    /// Covered twice: 16 agents sharing one login (the per-principal cap of
    /// 5 binds, as in the bakeoff) and 16 distinct principals over a cell
    /// cap of 5.
    #[tokio::test(start_paused = true)]
    async fn fleet_of_16_agents_over_a_cap_of_5_completes_with_no_rejects() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        for (config, shared_login) in [(fleet_config(30, 5), true), (fleet_config(5, 10), false)] {
            let controller = Arc::new(AdmissionController::new(config));
            controller.start_drain_loop();
            let running = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let shared_user = Uuid::now_v7();
            let mut agents = Vec::new();
            for agent in 0..16u64 {
                let (controller, running, peak) = (controller.clone(), running.clone(), peak.clone());
                let user = if shared_login { shared_user } else { Uuid::now_v7() };
                agents.push(tokio::spawn(with_wait_budget(std::time::Duration::from_secs(60), async move {
                    let mut rejects = 0;
                    for hunt in 0..10u64 {
                        match controller.acquire(&format!("agent{agent}-hunt{hunt}"), user, QueryPriority::Interactive).await {
                            Ok(permit) => {
                                let now = running.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                                peak.fetch_max(now, AtomicOrdering::SeqCst);
                                // Hunts of uneven cost (the bakeoff p50 was 3.5 s).
                                tokio::time::sleep(std::time::Duration::from_millis(500 + 300 * ((agent + hunt) % 7))).await;
                                running.fetch_sub(1, AtomicOrdering::SeqCst);
                                drop(permit);
                            }
                            Err(_) => rejects += 1,
                        }
                    }
                    rejects
                })));
            }
            let mut rejects = 0;
            for agent in agents {
                rejects += agent.await.expect("agent");
            }
            assert_eq!(rejects, 0, "every hunt waits inside its budget (shared login: {shared_login})");
            assert_eq!(peak.load(AtomicOrdering::SeqCst), 5, "the cap of 5 is kept, never raised");
            assert_eq!(controller.queue_depth().await, 0);
            assert_eq!(controller.stats().await.active_adhoc, 0);
        }
    }

    /// The budget is the only clock: it ends the wait with `QueueTimeout`
    /// (429 + Retry-After at the handler), is capped by `queue_timeout_ms`,
    /// and `0` fails fast. The expired waiter leaves the queue.
    #[tokio::test(start_paused = true)]
    async fn wait_budget_expiry_refuses_and_leaves_the_queue() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            queue_timeout_ms: 300,
            ..fleet_config(1, 1)
        }));
        controller.start_drain_loop();
        let holder = controller.acquire("holder", Uuid::now_v7(), QueryPriority::Interactive).await.unwrap();

        let started = tokio::time::Instant::now();
        let short = with_wait_budget(std::time::Duration::from_millis(100),
            controller.acquire("short", Uuid::now_v7(), QueryPriority::Interactive)).await;
        assert!(matches!(short, Err(AdmissionError::QueueTimeout { timeout_ms: 100 })), "{:?}", short.err());
        let waited = started.elapsed();
        assert!(waited >= std::time::Duration::from_millis(100) && waited < std::time::Duration::from_millis(150), "{waited:?}");
        assert_eq!(controller.queue_depth().await, 0, "an expired waiter leaves the queue");

        // An opt-in longer than the configured cap is capped.
        let capped = with_wait_budget(std::time::Duration::from_secs(3600),
            controller.acquire("capped", Uuid::now_v7(), QueryPriority::Interactive)).await;
        assert!(matches!(capped, Err(AdmissionError::QueueTimeout { timeout_ms: 300 })), "{:?}", capped.err());

        // Zero: fail fast, never queued.
        let started = tokio::time::Instant::now();
        let fast = with_wait_budget(std::time::Duration::ZERO,
            controller.acquire("fast", Uuid::now_v7(), QueryPriority::Interactive)).await;
        assert!(matches!(fast, Err(AdmissionError::QueueTimeout { timeout_ms: 0 })));
        assert!(started.elapsed() < std::time::Duration::from_millis(1), "never queued");

        // Inside the budget it waits and is admitted.
        let waiter_controller = controller.clone();
        let waiter = tokio::spawn(with_wait_budget(std::time::Duration::from_millis(250), async move {
            waiter_controller.acquire("waits", Uuid::now_v7(), QueryPriority::Interactive).await
        }));
        wait_for_depth(&controller, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(holder);
        waiter.await.unwrap().expect("admitted inside its budget");
    }

    /// No barging: an agent that releases and re-acquires at once queues
    /// behind the waiter that was already there.
    #[tokio::test]
    async fn releasing_agent_cannot_retake_its_slot_ahead_of_a_waiter() {
        let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
        controller.start_drain_loop();
        let (agent, waiter_user) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let held = controller.acquire("agent-1", agent, QueryPriority::Interactive).await.unwrap();
        let waiting = controller.clone();
        let waiter = tokio::spawn(async move { waiting.acquire("waiter", waiter_user, QueryPriority::Interactive).await });
        wait_for_depth(&controller, 1).await;
        // Release and re-acquire in the same task, before the drain can run.
        drop(held);
        let barged = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            controller.acquire("agent-2", agent, QueryPriority::Interactive),
        )
        .await;
        assert!(barged.is_err(), "the releasing agent queues instead of re-taking the slot");
        let waiter = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await.expect("the waiter got the freed slot").unwrap().unwrap();
        assert_eq!(controller.queue_depth().await, 0, "the abandoned re-acquire left the queue");
        drop(waiter);
    }

    #[test]
    fn header_budget_defaults_and_parses() {
        assert_eq!(request_wait_budget(None), DEFAULT_ADMISSION_WAIT);
        assert_eq!(request_wait_budget(Some("garbage")), DEFAULT_ADMISSION_WAIT);
        assert_eq!(request_wait_budget(Some(" 120000 ")), std::time::Duration::from_secs(120));
        assert_eq!(request_wait_budget(Some("0")), std::time::Duration::ZERO);
        assert_eq!(effective_wait(None, 300_000), std::time::Duration::from_secs(300));
        assert_eq!(effective_wait(Some(std::time::Duration::from_secs(900)), 300_000), std::time::Duration::from_secs(300));
        assert_eq!(effective_wait(Some(std::time::Duration::from_secs(5)), 300_000), std::time::Duration::from_secs(5));
    }

    /// A background job escapes its request's HTTP budget (it waits up to
    /// the configured cap); spawned request work keeps it via `inherit`.
    #[tokio::test]
    async fn async_jobs_escape_the_request_budget_and_side_tasks_inherit_it() {
        let five = std::time::Duration::from_secs(5);
        let job = with_wait_budget(five, without_wait_budget(async { current_wait_budget() })).await;
        assert_eq!(effective_wait(job, 300_000), std::time::Duration::from_secs(300));
        let side = with_wait_budget(five, async {
            tokio::spawn(crate::search::request_actor::inherit(async { current_wait_budget() })).await.unwrap()
        })
        .await;
        assert_eq!(side, Some(five));
        assert_eq!(current_wait_budget(), None);
    }

    fn synthetic(seq: u64, subject: AdmissionSubject, priority: QueryPriority) -> QueuedSearch {
        QueuedSearch {
            seq,
            job_id: format!("job-{seq}"),
            subject,
            require_distributed: false,
            priority,
            lane: AdmissionLane::Primary,
            class: QueryClass::Human,
            principal_tag: 0,
            tenant_tag: 0,
            tx: oneshot::channel().0,
        }
    }

    fn queue_of(entries: &[(AdmissionSubject, QueryPriority)]) -> WaitQueue {
        let mut queue = WaitQueue::default();
        for &(subject, priority) in entries {
            queue.push(synthetic(0, subject, priority));
        }
        queue
    }

    fn served(queue: &mut WaitQueue) -> Vec<u64> {
        let order = service_order(&mut queue.waiters);
        order.into_iter().map(|index| queue.waiters[index].seq).collect()
    }

    /// Serve the first waiter in line, as the drain does.
    fn serve_next(queue: &mut WaitQueue) -> u64 {
        let first = served(queue)[0];
        let search = queue.take(first).unwrap();
        queue.record_admitted(&search);
        first
    }

    /// Within a tenant, principals are served round-robin (a deep backlog
    /// from one agent cannot starve another), priority still first.
    #[test]
    fn service_order_is_round_robin_across_principals_within_a_tenant() {
        let greedy = shared_subject(0xa, 1);
        let other = shared_subject(0xa, 2);
        let mut queue = queue_of(&[
            (greedy, QueryPriority::Interactive),
            (greedy, QueryPriority::Interactive),
            (greedy, QueryPriority::Interactive),
            (other, QueryPriority::Interactive),
            (other, QueryPriority::Interactive),
            (greedy, QueryPriority::Analytics),
        ]);
        assert_eq!(served(&mut queue), vec![1, 4, 2, 5, 3, 6]);

        // Served history counts: a principal arriving once service is under
        // way joins the current round (behind at most one search of each
        // other principal), never behind greedy's whole backlog.
        assert_eq!(serve_next(&mut queue), 1);
        let late = queue.push(synthetic(0, shared_subject(0xa, 3), QueryPriority::Interactive));
        assert_eq!(served(&mut queue), vec![4, 2, 5, late, 3, 6]);
        for expected in [4, 2, 5, late, 3, 6] {
            assert_eq!(serve_next(&mut queue), expected);
        }
    }

    /// Across tenants, service alternates by each waiter's place in its own
    /// tenant's line: another tenant's backlog or higher priority never
    /// jumps this tenant's first waiter.
    #[test]
    fn service_order_never_lets_priority_or_backlog_cross_tenants() {
        let a = shared_subject(0xa, 1);
        let b = shared_subject(0xb, 1);
        let mut queue = queue_of(&[
            (a, QueryPriority::Interactive),
            (a, QueryPriority::Interactive),
            (a, QueryPriority::Interactive),
            (b, QueryPriority::Analytics),
        ]);
        assert_eq!(served(&mut queue), vec![1, 4, 2, 3]);
        // Taking turns holds as service goes on: B, served last, rejoins
        // level with A's next turn (not ahead of A's waiting backlog).
        assert_eq!(serve_next(&mut queue), 1);
        assert_eq!(serve_next(&mut queue), 4);
        let b_again = queue.push(synthetic(0, b, QueryPriority::Interactive));
        assert_eq!(served(&mut queue), vec![2, b_again, 3]);
        // Clocks of tenants without waiters are forgotten.
        while !queue.is_empty() {
            serve_next(&mut queue);
        }
        queue.prune_clocks();
        assert!(queue.principal_clocks.is_empty());
    }

    /// The fair order drives the real drain: a principal arriving behind
    /// another's backlog is admitted second, not seventh.
    #[tokio::test]
    async fn drain_serves_a_late_principal_before_anothers_backlog() {
        let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
        let holder = controller.acquire("holder", Uuid::from_u128(9), QueryPriority::Interactive).await.unwrap();
        let mut greedy = Vec::new();
        for index in 0..6u32 {
            let waiting = controller.clone();
            greedy.push(tokio::spawn(async move {
                waiting.acquire(&format!("greedy-{index}"), Uuid::from_u128(1), QueryPriority::Interactive).await
            }));
            wait_for_depth(&controller, index + 1).await;
        }
        let late_controller = controller.clone();
        let late = tokio::spawn(async move {
            late_controller.acquire("late", Uuid::from_u128(2), QueryPriority::Interactive).await
        });
        wait_for_depth(&controller, 7).await;
        assert_eq!(controller.queue_position("late").await, Some(2));
        controller.start_drain_loop();
        drop(holder);
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), greedy.remove(0))
            .await.expect("oldest admitted first").unwrap().unwrap();
        assert!(!late.is_finished());
        drop(first);
        let late = tokio::time::timeout(std::time::Duration::from_secs(5), late)
            .await.expect("late principal admitted second").unwrap().unwrap();
        assert_eq!(controller.queue_depth().await, 5, "the greedy backlog still waits");
        drop(late);
        for waiter in greedy {
            waiter.abort();
        }
    }

    /// A client that disconnects (its future is dropped) leaves the queue at
    /// once and its work is never started: the slot goes to the next live
    /// waiter, and no permit is ever granted to the dead one.
    #[tokio::test]
    async fn disconnected_waiter_leaves_the_queue_and_never_starts() {
        let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
        controller.start_drain_loop();
        let holder = controller.acquire("holder", Uuid::now_v7(), QueryPriority::Interactive).await.unwrap();
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gone_controller = controller.clone();
        let gone_started = started.clone();
        let gone = tokio::spawn(async move {
            let permit = gone_controller.acquire("gone", Uuid::now_v7(), QueryPriority::Interactive).await;
            gone_started.store(true, std::sync::atomic::Ordering::SeqCst);
            permit
        });
        wait_for_depth(&controller, 1).await;
        gone.abort();
        let _ = gone.await;
        assert_eq!(controller.queue_depth().await, 0, "the disconnected waiter left the queue");

        let live_controller = controller.clone();
        let live = tokio::spawn(async move {
            live_controller.acquire("live", Uuid::now_v7(), QueryPriority::Interactive).await
        });
        wait_for_depth(&controller, 1).await;
        drop(holder);
        let live = tokio::time::timeout(std::time::Duration::from_secs(5), live)
            .await.expect("live waiter admitted").unwrap().unwrap();
        assert!(!started.load(std::sync::atomic::Ordering::SeqCst), "the dead waiter's work never started");
        assert_eq!(controller.stats().await.active_adhoc, 1);
        drop(live);

        // A waiter whose receiver closed before the drain saw it (no guard
        // ran yet) is skipped by the drain, never admitted.
        let holder = controller.acquire("holder-2", Uuid::now_v7(), QueryPriority::Interactive).await.unwrap();
        lock_queue(&controller.queue).push(synthetic(0, AdmissionSubject::new(SearchTenantScope::Dedicated, Uuid::now_v7()), QueryPriority::Interactive));
        drop(holder);
        controller.drain_queue().await;
        assert_eq!(controller.queue_depth().await, 0);
        assert_eq!(controller.stats().await.active_adhoc, 0, "no permit for a closed waiter");
    }

    /// Tenant isolation of queue state: a tenant's queue position counts only
    /// its own waiters (another tenant's backlog is invisible), another
    /// tenant can neither see nor cancel its waiter by job id.
    #[tokio::test]
    async fn queue_position_and_cancel_never_cross_tenants() {
        let controller = AdmissionController::new(fleet_config(1, 10));
        let (a, b) = (shared_subject(0xa, 1), shared_subject(0xb, 1));
        let (b_tx, mut b_rx) = oneshot::channel();
        {
            let mut queue = lock_queue(&controller.queue);
            for _ in 0..3 {
                let mut search = synthetic(0, a, QueryPriority::Interactive);
                search.job_id = "a-job".into();
                queue.push(search);
            }
            let mut search = synthetic(0, b, QueryPriority::Interactive);
            search.job_id = "b-job".into();
            search.tx = b_tx;
            queue.push(search);
        }
        assert_eq!(controller.queue_position_for_scope("b-job", b.scope()).await, Some(1));
        assert_eq!(controller.queue_position_for_scope("b-job", a.scope()).await, None);
        controller.cancel_queued_for_scope("b-job", a.scope()).await;
        assert!(b_rx.try_recv().is_err(), "another tenant cannot cancel B's waiter");
        assert_eq!(controller.queue_depth().await, 4);
    }

    /// A waiter being tried by the drain (which awaits config and Redis)
    /// stays queued until admitted: its position holds, a cancel reaches it,
    /// and the permit taken for a waiter cancelled meanwhile is released.
    #[tokio::test]
    async fn waiter_stays_queued_and_cancellable_while_the_drain_tries_it() {
        let controller = Arc::new(AdmissionController::new(fleet_config(1, 10)));
        let holder = controller.acquire("holder", Uuid::now_v7(), QueryPriority::Interactive).await.unwrap();
        let waiting = controller.clone();
        let waiter = tokio::spawn(async move {
            waiting.acquire("waiter", Uuid::now_v7(), QueryPriority::Interactive).await
        });
        wait_for_depth(&controller, 1).await;
        drop(holder);

        // Park the drain inside `try_admit` (it awaits the config lock).
        let config = controller.config.lock().await;
        let draining = controller.clone();
        let drain = tokio::spawn(async move { draining.drain_queue().await });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!drain.is_finished(), "the drain is mid-pass");
        assert_eq!(controller.queue_depth().await, 1, "a waiter being tried is still queued");
        assert_eq!(controller.queue_position("waiter").await, Some(1));
        controller.cancel_queued("waiter").await;
        assert!(matches!(waiter.await.unwrap(), Err(AdmissionError::Cancelled)));

        drop(config);
        drain.await.unwrap();
        assert_eq!(controller.queue_depth().await, 0);
        assert_eq!(controller.stats().await.active_adhoc, 0, "no permit kept for the cancelled waiter");
    }

    /// The queue is bounded whatever the arrival rate: a burst of 1,000
    /// waiters holds `max_queue_depth` entries, the rest are refused at once
    /// with `QueueFull`, and memory does not grow with the burst.
    #[tokio::test]
    async fn queue_memory_is_bounded_under_a_burst() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            max_queue_depth: 50,
            ..fleet_config(1, 1)
        }));
        let _holder = controller.acquire("holder", Uuid::now_v7(), QueryPriority::Interactive).await.unwrap();
        let mut waiters = Vec::new();
        for index in 0..1_000u32 {
            let controller = controller.clone();
            waiters.push(tokio::spawn(async move {
                controller.acquire(&format!("burst-{index}"), Uuid::now_v7(), QueryPriority::Interactive).await
            }));
        }
        let mut refused = 0;
        let mut pending = Vec::new();
        for waiter in waiters {
            match tokio::time::timeout(std::time::Duration::from_millis(50), async { while !waiter.is_finished() { tokio::task::yield_now().await; } }).await {
                Ok(()) => match waiter.await.unwrap() {
                    Err(AdmissionError::QueueFull { depth: 50 }) => refused += 1,
                    other => panic!("unexpected: {:?}", other.err()),
                },
                Err(_) => pending.push(waiter),
            }
        }
        assert_eq!(pending.len(), 50);
        assert_eq!(refused, 950);
        assert_eq!(controller.queue_depth().await, 50);
        assert!(lock_queue(&controller.queue).waiters.capacity() <= 128, "queue storage stays at its bound");
        for waiter in pending {
            waiter.abort();
        }
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

    // ------------------------------------------------------------------
    // NAN-4703: agent-class guard (hard cap, lowest priority)
    // ------------------------------------------------------------------

    /// NAN-4703 over a real Redis/Dragonfly, two replicas: a shared
    /// tenant's agent permits stop at `agent_class_limit` (the script's -4),
    /// a human still admits into the reserved slot, another tenant's agents
    /// have their own key, and release removes the agent key too.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    #[ignore = "requires NANOSIEM_ADMISSION_TEST_REDIS_URL for a disposable Redis/Dragonfly"]
    async fn enterprise_shared_dragonfly_caps_agent_class_below_the_human_share() {
        let url = std::env::var("NANOSIEM_ADMISSION_TEST_REDIS_URL")
            .expect("NANOSIEM_ADMISSION_TEST_REDIS_URL must name a disposable database");
        let client = redis::Client::open(url).expect("create Redis client");
        let manager = client.get_connection_manager().await.expect("connect to disposable Redis/Dragonfly");
        let mut cleanup = manager.clone();
        redis::cmd("FLUSHDB").query_async::<()>(&mut cleanup).await.expect("clear disposable admission database");
        let config = AdmissionConfig {
            global_adhoc_limit: 30,
            shared_tenant_adhoc_limit: 4,
            per_user_limit: 10,
            max_queue_depth: 0,
            queue_timeout_ms: 100,
        };
        let first_replica = AdmissionController::new(config.clone());
        let second_replica = AdmissionController::new(config);
        first_replica.set_redis(manager.clone()).await;
        second_replica.set_redis(manager.clone()).await;
        let tenant_a = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa4703));
        let tenant_b = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb4703));

        let agents = with_query_class(QueryClass::Agent, async {
            let mut agents = Vec::new();
            for index in 0..agent_class_limit(4) {
                let replica = if index % 2 == 0 { &first_replica } else { &second_replica };
                agents.push(
                    replica
                        .acquire_for_scope(&format!("agent{index}"), tenant_a, Uuid::now_v7(), QueryPriority::Interactive)
                        .await
                        .expect("agent under its cap"),
                );
            }
            let over = second_replica
                .acquire_for_scope("agent-over", tenant_a, Uuid::now_v7(), QueryPriority::Interactive)
                .await;
            assert!(matches!(over, Err(AdmissionError::QueueFull { depth: 0 })), "agent over its cap is refused here (no queue)");
            let other = first_replica
                .acquire_for_scope("other-tenant", tenant_b, Uuid::now_v7(), QueryPriority::Interactive)
                .await
                .expect("tenant B's agents have their own cap");
            (agents, other)
        })
        .await;
        let human = second_replica
            .acquire_for_scope("human", tenant_a, Uuid::now_v7(), QueryPriority::Interactive)
            .await
            .expect("a human admits into the reserved share");
        let agent_count: i64 = redis::cmd("ZCARD")
            .arg(redis_agent_key(Some(Uuid::from_u128(0xa4703))))
            .query_async(&mut cleanup)
            .await
            .expect("read agent count");
        let tenant_count: i64 = redis::cmd("ZCARD")
            .arg(redis_tenant_key(Uuid::from_u128(0xa4703)))
            .query_async(&mut cleanup)
            .await
            .expect("read tenant count");
        assert_eq!((agent_count, tenant_count), (3, 4));

        drop((agents, human));
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let remaining: i64 = redis::cmd("EXISTS")
                    .arg(redis_agent_key(None))
                    .arg(redis_agent_key(Some(Uuid::from_u128(0xa4703))))
                    .arg(redis_agent_key(Some(Uuid::from_u128(0xb4703))))
                    .arg(redis_tenant_key(Uuid::from_u128(0xa4703)))
                    .query_async(&mut cleanup)
                    .await
                    .expect("read released keys");
                if remaining == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("release removes the agent and tenant keys");
    }

    #[test]
    fn agent_class_cap_leaves_the_human_reserve() {
        for (limit, reserved, agents) in [
            (1, 0, 1),
            (2, 1, 1),
            (4, 1, 3),
            (5, 1, 4),
            (8, 2, 6),
            (10, 2, 8),
            (30, 7, 23),
        ] {
            assert_eq!(human_reserved_slots(limit), reserved, "{limit}");
            assert_eq!(agent_class_limit(limit), agents, "{limit}");
            assert!(limit < 2 || agent_class_limit(limit) < limit, "{limit}: humans keep a slot");
        }
        assert_eq!(parse_query_class_header(Some(" Agent ")), QueryClass::Agent);
        for other in [None, Some(""), Some("human"), Some("agents")] {
            assert_eq!(parse_query_class_header(other), QueryClass::Human, "{other:?}");
        }
        // The script refuses an agent permit at its scope's cap and leases
        // the agent key only for agent permits.
        assert!(ACQUIRE_LUA.contains("redis.call('ZCARD', agent_tenant_key) >= agent_tenant_limit"));
        assert!(ACQUIRE_LUA.contains("redis.call('ZCARD', agent_cell_key) >= agent_cell_limit"));
        assert!(ACQUIRE_LUA.contains("return -4"));
        assert!(ACQUIRE_LUA.contains("lease(agent_cell_key)"));
        assert!(ACQUIRE_LUA.contains("lease(agent_tenant_key)"));
        // An agent credential is the agent class whatever the header says.
        for header in [None, Some("human"), Some("agent"), Some("")] {
            assert_eq!(resolve_query_class(true, header), QueryClass::Agent, "{header:?}");
        }
        assert_eq!(resolve_query_class(false, None), QueryClass::Human);
        assert_eq!(resolve_query_class(false, Some("agent")), QueryClass::Agent);
        // Every key nano Desktop mints for its agents.
        for name in ["nano Desktop \u{2014} agent tools (mbp)", "nano Desktop \u{2014} recon (mbp)", "nano Desktop \u{2014} hunt runner (mbp)", "nano Desktop \u{2014} hunt sweep (mbp)"] {
            assert!(is_agent_api_key_name(name), "{name}");
        }
        for name in ["ci ingest", "nano Desktop", "my nano Desktop \u{2014} key"] {
            assert!(!is_agent_api_key_name(name), "{name}");
        }
    }

    #[test]
    fn service_order_serves_humans_before_agents_within_a_tenant() {
        let tenant = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0x4703));
        let agent = AdmissionSubject::new(tenant, Uuid::now_v7());
        let human = AdmissionSubject::new(tenant, Uuid::now_v7());
        let mut queue = WaitQueue::default();
        for _ in 0..3 {
            let mut waiter = synthetic(0, agent, QueryPriority::Interactive);
            waiter.class = QueryClass::Agent;
            queue.push(waiter);
        }
        // An Analytics human still goes before Interactive agents.
        queue.push(synthetic(0, human, QueryPriority::Analytics));
        let order = service_order(&mut queue.waiters);
        assert_eq!(queue.waiters[order[0]].subject, human);
        assert!(order[1..].iter().all(|&index| queue.waiters[index].class == QueryClass::Agent));
    }

    /// Agents fill only their cap; a human arriving behind a queued agent is
    /// admitted at once into the reserved slot; the queued agent runs when
    /// an agent permit releases. Dedicated (process limit) and one shared
    /// tenant (its own limit; another tenant's agents are not counted).
    #[tokio::test]
    async fn agents_never_take_the_human_share() {
        let shared_a = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa4703));
        let shared_b = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb4703));
        for (config, scope) in [
            (fleet_config(4, 10), SearchTenantScope::Dedicated),
            (
                AdmissionConfig { shared_tenant_adhoc_limit: 4, ..fleet_config(30, 10) },
                shared_a,
            ),
        ] {
            let controller = Arc::new(AdmissionController::new(config));
            controller.start_drain_loop();
            let agent = |controller: Arc<AdmissionController>, scope: SearchTenantScope, job: String| async move {
                with_query_class(QueryClass::Agent, async move {
                    controller
                        .acquire_subject(&job, AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive)
                        .await
                })
                .await
            };
            let mut agents = Vec::new();
            for index in 0..agent_class_limit(4) {
                agents.push(agent(Arc::clone(&controller), scope, format!("agent{index}")).await.expect("agent under its cap"));
            }
            if scope == shared_a {
                // Another tenant's agents have their own cap.
                let other = agent(Arc::clone(&controller), shared_b, "other-tenant".into()).await;
                assert!(other.is_ok(), "tenant B is not capped by tenant A's agents");
            }
            let queued_agent = tokio::spawn(agent(Arc::clone(&controller), scope, "agent-over-cap".into()));
            wait_for_depth(&controller, 1).await;
            assert!(!queued_agent.is_finished(), "the agent over its cap waits");

            let human = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                controller.acquire_subject("human", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive),
            )
            .await
            .expect("the human is never queued behind capped agents")
            .expect("human admitted into the reserved share");
            assert_eq!(current_query_class(), QueryClass::Human);
            assert!(!queued_agent.is_finished());

            drop(agents.pop());
            let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), queued_agent)
                .await
                .expect("the queued agent runs once an agent permit releases")
                .expect("join")
                .expect("admitted");
            drop((admitted, human, agents));
        }
    }

    /// NAN-4703: in a shared cell, agents of many tenants together never
    /// take the cell's human reserve either: each tenant is under its own
    /// agent cap, but the cell-wide agent cap stops them, and a human of any
    /// tenant still admits.
    #[tokio::test]
    async fn agents_of_many_tenants_never_take_the_cells_human_share() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            shared_tenant_adhoc_limit: 4,
            ..fleet_config(8, 10)
        }));
        let mut agents = Vec::new();
        for tenant in 0..agent_class_limit(8) {
            let scope = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0x4703_0000 + u128::from(tenant)));
            agents.push(
                with_query_class(QueryClass::Agent, controller.acquire_subject("agent", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive))
                    .await
                    .expect("under the cell's agent cap"),
            );
        }
        let fresh_tenant = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0x4703_ffff));
        let over = with_query_class(
            QueryClass::Agent,
            with_wait_budget(std::time::Duration::ZERO, controller.acquire_subject("agent-over", AdmissionSubject::new(fresh_tenant, Uuid::now_v7()), false, QueryPriority::Interactive)),
        )
        .await;
        assert!(over.is_err(), "the cell's agent cap holds across tenants");
        for _ in 0..human_reserved_slots(8) {
            let human = with_wait_budget(
                std::time::Duration::ZERO,
                controller.acquire_subject("human", AdmissionSubject::new(fresh_tenant, Uuid::now_v7()), false, QueryPriority::Interactive),
            )
            .await
            .expect("humans keep the cell's reserve");
            agents.push(human);
        }
    }

    /// NAN-4703: agent waiters never fill a scope's queue (a human always
    /// finds a place in line), and a fail-fast agent never takes a free
    /// slot past a waiting human.
    #[tokio::test]
    async fn agents_never_fill_the_queue_or_barge_past_humans() {
        let scope = SearchTenantScope::Dedicated;
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            max_queue_depth: 4,
            ..fleet_config(1, 10)
        }));
        let held = controller
            .acquire_subject("holder", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive)
            .await
            .expect("first slot");
        let mut waiting = Vec::new();
        for index in 0..agent_class_limit(4) {
            let spawned = Arc::clone(&controller);
            waiting.push(tokio::spawn(with_query_class(QueryClass::Agent, async move {
                spawned
                    .acquire_subject(&format!("agent{index}"), AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive)
                    .await
            })));
            wait_for_depth(&controller, index + 1).await;
        }
        let over = with_query_class(
            QueryClass::Agent,
            controller.acquire_subject("agent-over", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive),
        )
        .await;
        assert!(matches!(over, Err(AdmissionError::QueueFull { .. })), "agents stop at their share of the queue");
        let human = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                controller
                    .acquire_subject("human", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive)
                    .await
            })
        };
        wait_for_depth(&controller, agent_class_limit(4) + 1).await;

        // Free the slot: a fail-fast agent must not take it past the human.
        drop(held);
        let barge = with_query_class(
            QueryClass::Agent,
            with_wait_budget(
                std::time::Duration::ZERO,
                controller.acquire_subject("agent-fail-fast", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive),
            ),
        )
        .await;
        assert!(barge.is_err(), "a fail-fast agent never barges past a waiting human");
        controller.drain_queue().await;
        let human = tokio::time::timeout(std::time::Duration::from_secs(5), human)
            .await
            .expect("the human is served first")
            .expect("join")
            .expect("human admitted");
        drop(human);
        for waiter in waiting {
            waiter.abort();
        }
    }

    /// NAN-4703: with Redis admission configured but not connected, an
    /// agent-class search fails closed (the local ledger counts one replica
    /// only), while a human search keeps the local fallback.
    #[tokio::test]
    async fn agents_fail_closed_without_configured_redis_humans_do_not() {
        let controller = AdmissionController::new(fleet_config(4, 10));
        controller.expect_redis();
        let scope = SearchTenantScope::Dedicated;
        let agent = with_query_class(
            QueryClass::Agent,
            controller.acquire_for_scope("agent", scope, Uuid::now_v7(), QueryPriority::Interactive),
        )
        .await;
        assert!(matches!(agent, Err(AdmissionError::Unavailable)), "agent fails closed");
        let human = controller
            .acquire_for_scope("human", scope, Uuid::now_v7(), QueryPriority::Interactive)
            .await;
        assert!(human.is_ok(), "a human keeps the local fallback");
    }

    /// NAN-4703: an agent permit's ledger counts return to zero on every
    /// exit: a normal drop, a cancelled holder task and a panicking one.
    #[tokio::test]
    async fn agent_ledger_counts_return_to_zero_on_every_exit() {
        let controller = Arc::new(AdmissionController::new(AdmissionConfig {
            shared_tenant_adhoc_limit: 4,
            ..fleet_config(8, 10)
        }));
        let tenant = Uuid::from_u128(0x4703);
        let scope = SearchTenantScope::EnterpriseShared(tenant);
        let acquire = move |controller: Arc<AdmissionController>| async move {
            with_query_class(QueryClass::Agent, controller.acquire_subject("agent", AdmissionSubject::new(scope, Uuid::now_v7()), false, QueryPriority::Interactive))
                .await
                .expect("agent admitted")
        };
        let dropped = acquire(Arc::clone(&controller)).await;
        let cancelled = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                let _permit = acquire(controller).await;
                std::future::pending::<()>().await;
            })
        };
        let panicked = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                let _permit = acquire(controller).await;
                panic!("search task panicked holding its permit");
            })
        };
        assert!(panicked.await.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while lock_ledger(&controller.ledger).agent_count(&None) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cancelled holder still holds its permit");
        cancelled.abort();
        let _ = cancelled.await;
        drop(dropped);
        let ledger = lock_ledger(&controller.ledger);
        assert_eq!((ledger.agent_count(&None), ledger.agent_count(&Some(tenant)), ledger.active()), (0, 0, 0));
    }
}
