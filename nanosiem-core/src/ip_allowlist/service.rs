// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist service with in-memory caching

use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::repository::{IpAllowlistRepository, IpAllowlistRepositoryError};
use super::types::*;

/// How often to refresh the cached allowlist from the database
const CACHE_TTL_SECS: u64 = 30;

/// NAN-5077: after a failed load, how long to wait before the next database
/// attempt. Every request in that window gets the last-known rule set (or,
/// when nothing was ever loaded, a refusal) without touching the pool, so an
/// exhausted pool is not hammered once per request.
const LOAD_RETRY_SECS: u64 = 5;

/// A failure streak is reported to the system-health bus only once it is
/// this many consecutive failed loads long, or this old — a single blip
/// (a failover, one timed-out query) is logged but pages nobody.
const REPORT_AFTER_FAILURES: u64 = 3;
const REPORT_AFTER_SECS: i64 = 30;

/// While a reported streak lasts, the condition is re-published this often
/// (it updates `last_seen_at`; it does not notify again).
const REPORT_HEARTBEAT_SECS: i64 = 300;

/// An active load-failure condition not seen for this long is an orphan (its
/// process died mid-outage): the SIEM health report stops counting it as
/// active, and the next process of the same service to load resolves it.
pub const LOAD_FAILED_STALE_SECS: i64 = 900;

#[derive(Error, Debug)]
pub enum IpAllowlistServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] IpAllowlistRepositoryError),
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Self-lockout protection: your current IP {0} would be blocked by this change")]
    SelfLockout(String),
    #[error("IP allowlist rules could not be loaded from the database")]
    RulesUnavailable,
}

/// Outcome of a request-path allowlist check (NAN-5077).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistDecision {
    /// The client may proceed.
    Allowed,
    /// The client is not on the allowlist.
    Denied,
    /// The rules have never been loaded in this process and the latest load
    /// failed, so the allowlist cannot tell — the request is refused (fail
    /// closed). Middleware answers 503, not 403: the client may well be
    /// listed, and the condition clears once the database is reachable.
    Unavailable,
}

impl AllowlistDecision {
    pub fn is_allowed(self) -> bool {
        self == Self::Allowed
    }
}

/// A parsed CIDR entry for fast matching
#[derive(Clone)]
struct CachedCidr {
    id: Uuid,
    scope: IpAllowlistScope,
    cidr_str: String,
    description: Option<String>,
    network: IpNetwork,
}

/// Simple IP network representation (avoids external ipnet dependency)
#[derive(Clone)]
enum IpNetwork {
    V4 { addr: u32, prefix_len: u8 },
    V6 { addr: u128, prefix_len: u8 },
}

impl IpNetwork {
    fn parse(cidr: &str) -> Result<Self, String> {
        // Handle bare IP addresses (no prefix) by adding /32 or /128
        let cidr = if !cidr.contains('/') {
            if cidr.contains(':') {
                format!("{}/128", cidr)
            } else {
                format!("{}/32", cidr)
            }
        } else {
            cidr.to_string()
        };

        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("invalid CIDR format: {}", cidr));
        }

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| format!("invalid prefix length: {}", parts[1]))?;
        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| format!("invalid IP address: {}", parts[0]))?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(format!("IPv4 prefix length {} exceeds 32", prefix_len));
                }
                Ok(IpNetwork::V4 {
                    addr: u32::from(v4),
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(format!("IPv6 prefix length {} exceeds 128", prefix_len));
                }
                Ok(IpNetwork::V6 {
                    addr: u128::from(v6),
                    prefix_len,
                })
            }
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpNetwork::V4 { addr, prefix_len }, IpAddr::V4(v4)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let ip_bits = u32::from(*v4);
                let mask = u32::MAX.checked_shl(32 - *prefix_len as u32).unwrap_or(0);
                (ip_bits & mask) == (*addr & mask)
            }
            (IpNetwork::V6 { addr, prefix_len }, IpAddr::V6(v6)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let ip_bits = u128::from(*v6);
                let mask = u128::MAX.checked_shl(128 - *prefix_len as u32).unwrap_or(0);
                (ip_bits & mask) == (*addr & mask)
            }
            // IPv4 network can't contain IPv6 address and vice versa
            _ => false,
        }
    }
}

/// A successfully loaded rule set.
struct RuleSet {
    entries: Vec<CachedCidr>,
    has_any_rules: bool,
}

/// Cached allowlist state.
///
/// NAN-5077: `rules` is the LAST-KNOWN-GOOD rule set and survives both a
/// failed refresh and [`IpAllowlistService::invalidate_cache`]. A failed load
/// used to be cached as "no rules", which switched a configured allowlist off
/// for every client for as long as PostgreSQL was unreachable.
#[derive(Default)]
struct CacheSlot {
    rules: Option<Arc<RuleSet>>,
    /// Until when the slot may be served without a database round trip.
    /// `None` forces the next check to reload.
    fresh_until: Option<std::time::Instant>,
    /// Set while loads keep failing; cleared (and resolved) on recovery.
    failure_streak: Option<FailureStreak>,
    /// Whether this process has had a successful load yet; the first one
    /// clears conditions left active by an earlier run (NAN-5077).
    loaded_once: bool,
}

/// An unbroken run of failed loads (NAN-5077).
struct FailureStreak {
    failures: u64,
    since: chrono::DateTime<chrono::Utc>,
    last_error: String,
    /// Whether the streak began with no rule set at all (fail closed).
    failed_closed: bool,
    /// When the streak was last published to the system-health bus; `None`
    /// until it crosses the reporting threshold.
    reported_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The latest report task. Each report waits for the one before it, and
    /// the recovery waits for the last, so a late publish can never land
    /// after the resolve and open a fresh (notifying) condition.
    last_report: Option<tokio::task::JoinHandle<()>>,
}

impl FailureStreak {
    /// Whether this failure should publish (first crossing of the threshold,
    /// or a heartbeat while a reported streak lasts).
    fn report_due(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        match self.reported_at {
            None => {
                self.failures >= REPORT_AFTER_FAILURES
                    || (now - self.since).num_seconds() >= REPORT_AFTER_SECS
            }
            Some(at) => (now - at).num_seconds() >= REPORT_HEARTBEAT_SECS,
        }
    }
}

/// `system_health_events` dedup key prefix for allowlist load failures. The
/// SIEM health report reads these back (it runs in `nanosiem-jobs`, so an
/// in-memory flag in nanosiem-api / nanosiem-search would never reach it).
/// Full key: `<prefix><component>:<instance>` — one lifecycle per PROCESS,
/// because each replica loads (and fails, and recovers) on its own.
pub const LOAD_FAILED_DEDUP_PREFIX: &str = "ip_allowlist:load_failed:";

/// IP Allowlist service with in-memory cached CIDR matching
#[derive(Clone)]
pub struct IpAllowlistService {
    pool: PgPool,
    cache: Arc<RwLock<CacheSlot>>,
    /// Emergency bypass via NANO_IP_ALLOWLIST_DISABLED env var
    disabled: bool,
    /// Which service enforces this allowlist (`nanosiem-api`,
    /// `nanosiem-search`); names the system-health condition.
    component: &'static str,
    /// This process's identity (pod name / container hostname).
    instance: String,
}

impl IpAllowlistService {
    pub fn new(pool: PgPool) -> Self {
        let disabled = std::env::var("NANO_IP_ALLOWLIST_DISABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        if disabled {
            tracing::warn!("IP allowlist is DISABLED via NANO_IP_ALLOWLIST_DISABLED env var");
        }

        Self {
            pool,
            cache: Arc::new(RwLock::new(CacheSlot::default())),
            disabled,
            component: "nanosiem",
            instance: instance_identity(),
        }
    }

    /// Name the enforcing service in the system-health condition raised when
    /// the rules cannot be loaded.
    pub fn with_component(mut self, component: &'static str) -> Self {
        self.component = component;
        self
    }

    /// Override the process identity used in the system-health condition
    /// (defaults to the pod name / container hostname).
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = instance.into().chars().take(128).collect();
        self
    }

    fn repository(&self) -> IpAllowlistRepository {
        IpAllowlistRepository::new(self.pool.clone())
    }

    /// Check if an IP is allowed for a given scope.
    ///
    /// Returns true if:
    /// - The allowlist is disabled via env var
    /// - No enabled rules exist (feature not active)
    /// - The IP is a loopback address (127.0.0.1, ::1)
    /// - The IP matches a global or scope-specific CIDR rule
    ///
    /// Returns false (fail closed) when the rules have never loaded and the
    /// latest load failed (NAN-5077).
    pub async fn is_allowed(&self, ip_str: &str, scope: IpAllowlistScope) -> bool {
        // Emergency bypass
        if self.disabled {
            return true;
        }

        // Always allow loopback
        if is_loopback_literal(ip_str) {
            return true;
        }

        self.rules_allow(ip_str, scope).await.is_allowed()
    }

    /// Request-path check (NAN-5015): like [`Self::is_allowed`], but the
    /// loopback pass applies only when the address is the TCP PEER itself.
    ///
    /// A loopback address read from a forwarded header is a claim, not an
    /// observation — `CF-Connecting-IP: 127.0.0.1` used to bypass every rule.
    /// Such an address is evaluated against the rules like any other.
    ///
    /// NAN-5077: when the rules cannot be loaded and nothing was loaded
    /// before, the answer is [`AllowlistDecision::Unavailable`] — never
    /// "allowed". The socket-loopback pass and `NANO_IP_ALLOWLIST_DISABLED`
    /// stay available as the operator's way back in.
    pub async fn is_allowed_client(
        &self,
        ip_str: &str,
        from_socket: bool,
        scope: IpAllowlistScope,
    ) -> AllowlistDecision {
        if self.disabled {
            return AllowlistDecision::Allowed;
        }
        if from_socket && is_loopback_literal(ip_str) {
            return AllowlistDecision::Allowed;
        }
        self.rules_allow(ip_str, scope).await
    }

    async fn rules_allow(&self, ip_str: &str, scope: IpAllowlistScope) -> AllowlistDecision {
        // Parse the IP
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(ip = %ip_str, "Failed to parse IP for allowlist check — denying");
                return AllowlistDecision::Denied;
            }
        };

        // Refresh cache if needed. `None`: never loaded and the load failed.
        let Some(rules) = self.get_or_refresh_cache().await else {
            return AllowlistDecision::Unavailable;
        };

        if rules_match(&rules, &ip, scope) {
            AllowlistDecision::Allowed
        } else {
            AllowlistDecision::Denied
        }
    }

    /// Force a cache refresh (call after CRUD operations). The last-known
    /// rule set is kept as the fallback should that refresh fail.
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.fresh_until = None;
    }

    /// Load and parse the enabled rules straight from the database.
    async fn load_rules(&self) -> Result<RuleSet, IpAllowlistRepositoryError> {
        let entries = self.repository().list(None).await?;
        let has_any_rules = entries.iter().any(|e| e.enabled);

        let cached: Vec<CachedCidr> = entries
            .into_iter()
            .filter(|e| e.enabled)
            .filter_map(|e| {
                match IpNetwork::parse(&e.cidr) {
                    Ok(network) => Some(CachedCidr {
                        id: e.id,
                        scope: e.scope,
                        cidr_str: e.cidr,
                        description: e.description,
                        network,
                    }),
                    Err(err) => {
                        tracing::warn!(cidr = %e.cidr, error = %err, "Skipping invalid CIDR in allowlist");
                        None
                    }
                }
            })
            .collect();

        Ok(RuleSet {
            entries: cached,
            has_any_rules,
        })
    }

    /// The current rule set: cached, freshly loaded, or — when a reload
    /// fails — the last-known one. `None` only when no rule set has ever
    /// loaded in this process and the latest attempt failed; callers must
    /// treat that as "refuse" (NAN-5077).
    async fn get_or_refresh_cache(&self) -> Option<Arc<RuleSet>> {
        // Fast path: within the TTL (or within the retry back-off after a
        // failure), serve what the slot holds.
        {
            let cache = self.cache.read().await;
            if cache
                .fresh_until
                .is_some_and(|until| std::time::Instant::now() < until)
            {
                return cache.rules.clone();
            }
        }

        // Slow path: refresh from database
        match self.load_rules().await {
            Ok(rules) => {
                let rules = Arc::new(rules);
                let mut cache = self.cache.write().await;
                cache.rules = Some(rules.clone());
                cache.fresh_until = Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(CACHE_TTL_SECS),
                );
                let recovered = cache.failure_streak.take();
                let first_load = !std::mem::replace(&mut cache.loaded_once, true);
                drop(cache);
                let mut last_report = None;
                let mut reported = false;
                if let Some(streak) = recovered {
                    tracing::info!(
                        failures = streak.failures,
                        since = %streak.since,
                        "IP allowlist rules loaded again after failed loads"
                    );
                    reported = streak.reported_at.is_some();
                    last_report = streak.last_report;
                }
                if reported || first_load {
                    self.settle_conditions(last_report, first_load);
                }
                Some(rules)
            }
            Err(e) => {
                let mut cache = self.cache.write().await;
                cache.fresh_until = Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(LOAD_RETRY_SECS),
                );
                let last_known = cache.rules.clone();
                let now = chrono::Utc::now();
                let streak = cache.failure_streak.get_or_insert_with(|| FailureStreak {
                    failures: 0,
                    since: now,
                    last_error: String::new(),
                    failed_closed: last_known.is_none(),
                    reported_at: None,
                    last_report: None,
                });
                streak.failures += 1;
                streak.last_error = e.to_string();
                if streak.report_due(now) {
                    // Best effort: PostgreSQL is likely the thing that is
                    // down, and then this publish fails too (logged).
                    let previous = streak.last_report.take();
                    let event = self.load_failed_event(streak);
                    streak.last_report = Some(self.publish_condition(previous, event));
                    streak.reported_at = Some(now);
                }
                drop(cache);
                if last_known.is_some() {
                    tracing::warn!(
                        error = %e,
                        "Failed to refresh IP allowlist from database — enforcing the last-known rule set"
                    );
                } else {
                    tracing::error!(
                        error = %e,
                        "Failed to load IP allowlist from database and no rule set was ever loaded — \
                         refusing non-loopback clients on allowlist-protected routes (503) until it loads. \
                         Break-glass: connect from loopback inside the container/pod (docker exec / kubectl exec), or set NANO_IP_ALLOWLIST_DISABLED=true"
                    );
                }
                last_known
            }
        }
    }

    fn load_failed_dedup_key(&self) -> String {
        format!("{LOAD_FAILED_DEDUP_PREFIX}{}:{}", self.component, self.instance)
    }

    fn load_failed_event(&self, streak: &FailureStreak) -> crate::system_health::PublishHealthEvent {
        use crate::system_health::{HealthCategory, HealthSeverity, PublishHealthEvent};
        let who = format!("{} ({})", self.component, self.instance);
        let (severity, title, effect) = if streak.failed_closed {
            (
                HealthSeverity::Critical,
                format!("{who}: IP allowlist rules cannot be loaded — refusing clients"),
                "No rule set was loaded before, so allowlist-protected routes answer 503 to every non-loopback client.",
            )
        } else {
            (
                HealthSeverity::High,
                format!("{who}: IP allowlist rules cannot be refreshed — last-known rules enforced"),
                "The rules loaded last are still enforced; changes made since are not in effect.",
            )
        };
        let error: String = streak.last_error.chars().take(500).collect();
        let mut event = PublishHealthEvent::new(
            self.load_failed_dedup_key(),
            HealthCategory::Service,
            severity,
            title,
            format!(
                "Loading the IP allowlist rules from PostgreSQL has failed {} times since {} \
                 (last error: {error}). {effect}",
                streak.failures,
                streak.since.to_rfc3339(),
            ),
            "ip_allowlist",
            self.component,
        );
        event.resource_id = Some(self.instance.clone());
        event.resource_name = Some(self.component.to_string());
        event.diagnostic_context = serde_json::json!({
            "instance": self.instance,
            "failures": streak.failures,
            "since": streak.since,
            "failed_closed": streak.failed_closed,
        });
        event.remediation = Some(
            "Restore PostgreSQL connectivity; enforcement recovers on the next successful load. \
             Break-glass: connect from loopback inside the container or pod (docker exec / \
             kubectl exec; a host-published port is not loopback), or restart the service with \
             NANO_IP_ALLOWLIST_DISABLED=true. See \
             docs/administration/ip-allowlist.md."
                .to_string(),
        );
        event
    }

    /// Publish after `previous` has finished (reports stay in order).
    fn publish_condition(
        &self,
        previous: Option<tokio::task::JoinHandle<()>>,
        event: crate::system_health::PublishHealthEvent,
    ) -> tokio::task::JoinHandle<()> {
        let repo = crate::system_health::SystemHealthRepository::new(self.pool.clone());
        tokio::spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            if let Err(e) = repo.publish(&event).await {
                tracing::debug!(error = %e, "Could not record IP allowlist load failure (database unreachable)");
            }
        })
    }

    /// After a successful load: resolve this process's condition, and on the
    /// process's FIRST load also any of this service's conditions whose
    /// process stopped reporting long ago (replaced pods). Resolving the own
    /// key on the first load clears what a previous run of this instance
    /// left active (crash mid-outage); a live failing replica keeps its own
    /// fresh with heartbeats and is not touched.
    ///
    /// Never publishes — a publish here would OPEN a condition (and page)
    /// whenever the failure report had not reached the database. Runs after
    /// `last_report`, so a late publish cannot land after the resolve.
    fn settle_conditions(&self, last_report: Option<tokio::task::JoinHandle<()>>, sweep_stale: bool) {
        let repo = crate::system_health::SystemHealthRepository::new(self.pool.clone());
        let own_key = self.load_failed_dedup_key();
        let component_prefix = format!("{LOAD_FAILED_DEDUP_PREFIX}{}:", self.component);
        tokio::spawn(async move {
            if let Some(last_report) = last_report {
                let _ = last_report.await;
            }
            if let Err(e) = repo.resolve_by_dedup_key(&own_key).await {
                tracing::warn!(error = %e, "Could not resolve IP allowlist load-failure condition");
            }
            if !sweep_stale {
                return;
            }
            let stale_before =
                chrono::Utc::now() - chrono::Duration::seconds(LOAD_FAILED_STALE_SECS);
            match repo.resolve_stale_by_prefix(&component_prefix, stale_before).await {
                Ok(resolved) if !resolved.is_empty() => tracing::info!(
                    count = resolved.len(),
                    "Resolved stale IP allowlist load-failure conditions"
                ),
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "Could not clear stale IP allowlist conditions"),
            }
        });
    }

    // ========================================================================
    // CRUD operations (delegate to repository)
    // ========================================================================

    /// List all allowlist entries, optionally filtered by scope
    pub async fn list(
        &self,
        scope: Option<IpAllowlistScope>,
    ) -> Result<Vec<IpAllowlistEntry>, IpAllowlistServiceError> {
        Ok(self.repository().list(scope).await?)
    }

    /// Get a single entry by ID
    pub async fn get(&self, id: Uuid) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        Ok(self.repository().get(id).await?)
    }

    /// Create a new allowlist entry
    pub async fn create(
        &self,
        entry: CreateIpAllowlistEntry,
        created_by: Option<Uuid>,
    ) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        // Validate CIDR
        IpNetwork::parse(&entry.cidr).map_err(|e| IpAllowlistServiceError::InvalidCidr(e))?;

        let result = self.repository().create(&entry, created_by).await?;
        self.invalidate_cache().await;
        Ok(result)
    }

    /// Update an existing allowlist entry
    pub async fn update(
        &self,
        id: Uuid,
        update: UpdateIpAllowlistEntry,
    ) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        // Validate CIDR if provided
        if let Some(ref cidr) = update.cidr {
            IpNetwork::parse(cidr).map_err(|e| IpAllowlistServiceError::InvalidCidr(e))?;
        }

        let result = self.repository().update(id, &update).await?;
        self.invalidate_cache().await;
        Ok(result)
    }

    /// Delete an allowlist entry
    pub async fn delete(&self, id: Uuid) -> Result<(), IpAllowlistServiceError> {
        self.repository().delete(id).await?;
        self.invalidate_cache().await;
        Ok(())
    }

    /// Validate that a given IP would still be allowed after proposed changes.
    /// Used for self-lockout protection.
    pub async fn validate_no_self_lockout(
        &self,
        admin_ip: &str,
        scope: IpAllowlistScope,
    ) -> Result<(), IpAllowlistServiceError> {
        let ip: IpAddr = admin_ip
            .parse()
            .map_err(|_| IpAllowlistServiceError::InvalidIp(admin_ip.to_string()))?;

        // Check the rules as now stored, not a cached copy: the write being
        // validated has just happened. If they cannot be read, the change
        // stands (as before NAN-5077); enforcement fails closed on its own.
        let rules = match self.load_rules().await {
            Ok(rules) => rules,
            Err(e) => {
                tracing::warn!(error = %e, "Could not re-read IP allowlist for self-lockout check");
                return Ok(());
            }
        };

        if rules_match(&rules, &ip, scope) {
            Ok(())
        } else {
            Err(IpAllowlistServiceError::SelfLockout(admin_ip.to_string()))
        }
    }

    /// Test an IP against the current allowlist
    pub async fn test_ip(
        &self,
        ip_str: &str,
        scope: Option<IpAllowlistScope>,
    ) -> Result<TestIpResponse, IpAllowlistServiceError> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| IpAllowlistServiceError::InvalidIp(ip_str.to_string()))?;

        let cache = self
            .get_or_refresh_cache()
            .await
            .ok_or(IpAllowlistServiceError::RulesUnavailable)?;

        if !cache.has_any_rules {
            return Ok(TestIpResponse {
                ip: ip_str.to_string(),
                allowed: true,
                matched_rules: vec![],
                allowlist_active: false,
            });
        }

        let mut matched_rules = Vec::new();

        for entry in &cache.entries {
            // If testing a specific scope, only check global + that scope
            if let Some(test_scope) = scope {
                if entry.scope != IpAllowlistScope::Global && entry.scope != test_scope {
                    continue;
                }
            }

            if entry.network.contains(&ip) {
                matched_rules.push(MatchedRule {
                    id: entry.id,
                    scope: entry.scope,
                    cidr: entry.cidr_str.clone(),
                    description: entry.description.clone(),
                });
            }
        }

        let allowed = !matched_rules.is_empty();

        Ok(TestIpResponse {
            ip: ip_str.to_string(),
            allowed,
            matched_rules,
            allowlist_active: true,
        })
    }

    /// Get allowlist status summary
    pub async fn status(&self) -> Result<IpAllowlistStatus, IpAllowlistServiceError> {
        let entries = self.repository().list(None).await?;
        let enabled_rules = entries.iter().filter(|e| e.enabled).count();

        let mut rules_by_scope = std::collections::HashMap::new();
        for entry in &entries {
            if entry.enabled {
                *rules_by_scope
                    .entry(entry.scope.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        Ok(IpAllowlistStatus {
            active: enabled_rules > 0,
            total_rules: entries.len(),
            enabled_rules,
            rules_by_scope,
        })
    }
}

/// This process's identity for its system-health lifecycle: the pod name or
/// container hostname, as the distributed scheduler identifies nodes.
fn instance_identity() -> String {
    let id = crate::detection::distributed_scheduler::generate_node_id();
    id.chars().take(128).collect()
}

/// Whether `rules` let `ip` through for `scope`. No enabled rules means the
/// allowlist is inactive (allow everything) — that is only ever concluded
/// from a SUCCESSFUL load.
fn rules_match(rules: &RuleSet, ip: &IpAddr, scope: IpAllowlistScope) -> bool {
    if !rules.has_any_rules {
        return true;
    }
    rules.entries.iter().any(|entry| {
        (entry.scope == IpAllowlistScope::Global || entry.scope == scope)
            && entry.network.contains(ip)
    })
}

/// Loopback literal as the allowlist has always recognised it.
fn is_loopback_literal(ip_str: &str) -> bool {
    ip_str == "127.0.0.1" || ip_str == "::1"
}

#[cfg(test)]
impl IpAllowlistService {
    /// A service whose cache is pre-seeded with enabled `cidrs` (no database
    /// round trip within the cache TTL).
    pub(crate) fn with_cached_rules(cidrs: &[(&str, IpAllowlistScope)]) -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        let entries = cidrs
            .iter()
            .map(|(cidr, scope)| CachedCidr {
                id: Uuid::nil(),
                scope: *scope,
                cidr_str: cidr.to_string(),
                description: None,
                network: IpNetwork::parse(cidr).expect("test cidr"),
            })
            .collect();
        Self {
            pool,
            cache: Arc::new(RwLock::new(CacheSlot {
                rules: Some(Arc::new(RuleSet {
                    entries,
                    has_any_rules: true,
                })),
                fresh_until: Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(CACHE_TTL_SECS),
                ),
                failure_streak: None,
                loaded_once: true,
            })),
            disabled: false,
            component: "test",
            instance: "test-0".into(),
        }
    }

    /// A service whose database is unreachable (nothing listens on port 1)
    /// and whose cache has never been filled.
    pub(crate) fn with_unreachable_database() -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        Self {
            pool,
            cache: Arc::new(RwLock::new(CacheSlot::default())),
            disabled: false,
            component: "test",
            instance: "test-0".into(),
        }
    }

    /// Whether the current streak has been published to the health bus.
    pub(crate) async fn streak_reported(&self) -> bool {
        self.cache
            .read()
            .await
            .failure_streak
            .as_ref()
            .is_some_and(|s| s.reported_at.is_some())
    }

    /// Failed loads in the current streak (0 = none).
    pub(crate) async fn failure_streak_len(&self) -> u64 {
        self.cache.read().await.failure_streak.as_ref().map_or(0, |s| s.failures)
    }

    /// Mark the cache as due for a reload, as if its TTL had elapsed.
    pub(crate) async fn expire_cache_for_test(&self) {
        self.cache.write().await.fresh_until = None;
    }
}

#[cfg(test)]
#[path = "service_client_ip_tests.rs"]
mod service_client_ip_tests;

#[cfg(test)]
#[path = "service_fail_closed_tests.rs"]
mod service_fail_closed_tests;
