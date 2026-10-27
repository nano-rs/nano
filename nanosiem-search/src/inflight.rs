// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4664: in-flight sharing of identical searches.
//!
//! A fleet of agents hunting at once sends the same search many times over
//! (16 bakeoff agents ran the same 10 hunts). Identical searches that are
//! already running share ONE run: the first request leads (it takes the
//! admission slot and executes), every identical request that arrives while
//! it runs follows and receives a clone of the leader's result. Followers
//! never take an admission slot.
//!
//! This is not a cache: the result is computed now, for this moment, so it
//! applies even to `use_cache: false` and to `x-nano-cache-bypass` refreshes.
//! A finished run is forgotten at once; the next identical request leads a
//! fresh run.
//!
//! **Identity** is [`crate::cache::SearchResultCache::inflight_key_for`]: the
//! server-resolved tenant (strictly per tenant), its serving generation, the
//! caller's effective source and artifact deny sets (RBAC scope), its
//! authority fingerprint (plan, prevalence, retention, priority), the
//! normalized query, `use_cache`, the exact time bounds, limit, offset, every
//! result-shaping flag and the dataset. [`share_eligible`] keeps out
//! anything a follower must not inherit from another caller's run.
//!
//! **Leader loss.** If the leader is cancelled (its client left, it escalated
//! to a durable job, a `DELETE` killed it) or fails for a reason of its own
//! (admission, a dependency blip), no follower fails with it: one follower
//! becomes the new leader and runs the search, the rest follow that one. A
//! failure the query itself determines (parse, budget, timeout) is handed to
//! every follower at once instead of being re-run one follower at a time.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use metrics::counter;
use tokio::sync::watch;

/// How a request's result was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// This request ran the search.
    Leader,
    /// This request received an identical concurrent run's result.
    Follower,
}

/// What a finished leader publishes to its followers: its result, or a
/// failure the query itself determines (see [`InFlight::run`]).
type Published<V, E> = Option<Result<V, E>>;
type Runs<V, E> = Mutex<HashMap<String, watch::Receiver<Published<V, E>>>>;

/// Registry of runs in flight, keyed by search identity. Entries live only
/// while their leader runs, so its size is bounded by concurrent requests;
/// a follower holds one channel receiver, never a slot in a list.
pub(crate) struct InFlight<V, E> {
    runs: Runs<V, E>,
}

impl<V, E> Default for InFlight<V, E> {
    fn default() -> Self {
        Self { runs: Mutex::new(HashMap::new()) }
    }
}

/// Removes the leader's entry when its run ends or its future is dropped
/// (cancel, escalation, panic). Declared after the sender, so it drops
/// first: woken followers never find the dead entry.
struct LeaderGuard<'a, V, E> {
    runs: &'a Runs<V, E>,
    key: &'a str,
    mine: watch::Receiver<Published<V, E>>,
}

impl<V, E> Drop for LeaderGuard<'_, V, E> {
    fn drop(&mut self) {
        let mut runs = self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if runs.get(self.key).is_some_and(|current| current.same_channel(&self.mine)) {
            runs.remove(self.key);
        }
    }
}

impl<V: Clone, E> InFlight<V, E> {
    /// Number of runs in flight (tests, gauges).
    pub(crate) fn len(&self) -> usize {
        self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    /// Run `lead()` as this key's leader, or follow the identical run in
    /// flight. `shared_failure` copies a leader's error that the QUERY
    /// determines (it would fail the same way for every follower: a parse or
    /// SQL error, a resource budget, a timeout); followers receive that copy
    /// instead of re-running the search one after another. Any other failure
    /// (an admission refusal, a cancel, a dependency blip) and a cancelled
    /// leader hand the run to ONE follower, which calls `lead` again.
    pub(crate) async fn run<F, Fut>(&self, key: &str, mut lead: F, shared_failure: fn(&E) -> Option<E>) -> (Result<V, E>, Role)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        loop {
            let follow = {
                let mut runs = self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                match runs.get(key) {
                    Some(running) => Ok(running.clone()),
                    None => {
                        let (tx, rx) = watch::channel(None);
                        runs.insert(key.to_owned(), rx.clone());
                        Err((tx, rx))
                    }
                }
            };
            match follow {
                Ok(mut running) => {
                    loop {
                        let published = match &*running.borrow_and_update() {
                            Some(Ok(value)) => Some(Ok(value.clone())),
                            Some(Err(error)) => shared_failure(error).map(Err),
                            None => None,
                        };
                        if let Some(result) = published {
                            counter!("nanosiem_search_inflight_total", "role" => "follower").increment(1);
                            return (result, Role::Follower);
                        }
                        if running.changed().await.is_err() {
                            break;
                        }
                    }
                    // The leader ended without a shareable outcome (cancelled
                    // or a caller-specific failure): take over.
                    counter!("nanosiem_search_inflight_takeovers_total").increment(1);
                }
                Err((tx, mine)) => {
                    let guard = LeaderGuard { runs: &self.runs, key, mine };
                    counter!("nanosiem_search_inflight_total", "role" => "leader").increment(1);
                    let result = lead().await;
                    let published = match &result {
                        Ok(value) => Some(Ok(value.clone())),
                        Err(error) => shared_failure(error).map(Err),
                    };
                    if published.is_some() {
                        let _ = tx.send(published);
                    }
                    drop(guard);
                    return (result, Role::Leader);
                }
            }
        }
    }
}

/// A leader's failure that every identical follower would also hit, copied
/// for them (NAN-4664). Caller- or moment-specific failures (admission, a
/// cancel, an unavailable dependency, a database error) return `None`: a
/// follower takes the run over instead.
pub(crate) fn query_determined_failure(error: &nanosiem_core::SearchError) -> Option<nanosiem_core::SearchError> {
    use nanosiem_core::SearchError as E;
    Some(match error {
        E::ParseError(message) => E::ParseError(message.clone()),
        E::StructuredParseError { message, position, line, column, token, expected, suggestions, formatted } => E::StructuredParseError {
            message: message.clone(), position: *position, line: *line, column: *column, token: token.clone(),
            expected: expected.clone(), suggestions: suggestions.clone(), formatted: formatted.clone(),
        },
        E::FieldNotFound { field, suggestions, message } => E::FieldNotFound { field: field.clone(), suggestions: suggestions.clone(), message: message.clone() },
        E::SqlGenError(message) => E::SqlGenError(message.clone()),
        E::SqlValidationError(message) => E::SqlValidationError(message.clone()),
        E::InvalidTimeRange => E::InvalidTimeRange,
        E::Timeout(ms) => E::Timeout(*ms),
        E::ResponseTooLarge(size, limit) => E::ResponseTooLarge(*size, *limit),
        E::ResourceExhausted(kind) => E::ResourceExhausted(kind.clone()),
        E::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes } => E::ColdScanTooLarge {
            needed_bytes: *needed_bytes, ceiling_bytes: *ceiling_bytes, background_ceiling_bytes: *background_ceiling_bytes,
        },
        _ => return None,
    })
}

/// Whether a search may share an identical in-flight run (NAN-4664). Only
/// when nothing about the run depends on who asked beyond the identity key:
///
/// - not a debug run, a progressive view, a request-bound risk view or a
///   run under per-request perf overrides (their execution differs from an
///   ordinary run);
/// - not a query that reads state outside the serving generation or is
///   billed per member: lookups, IOC feeds, `| ai` (NAN-2922);
/// - not a query naming a source the caller cannot see: that attempt is
///   audited from the caller's own run (NAN-3222), so it always leads;
/// - a shared tenant only with its serving generation (as the cache).
pub(crate) fn share_eligible(
    query: &str,
    deny_set: &std::collections::BTreeSet<String>,
    shared_tenant: bool,
    has_generation: bool,
    debug: bool,
    progressive_views: bool,
    risk_bound: bool,
) -> bool {
    // A request-bound risk view reads the tenant's live clear state as the
    // requesting member: it always runs on its own.
    if debug || progressive_views || risk_bound || nanosiem_core::search::lake_debug::perf_overrides().is_some() {
        return false;
    }
    if shared_tenant && !has_generation {
        return false;
    }
    if crate::cache::reads_state_outside_the_generation(query) {
        return false;
    }
    if deny_set.is_empty() {
        return true;
    }
    match nanosiem_core::query::parse_query(query) {
        Ok(parsed) => nanosiem_core::search::denied_source_audit::denied_sources_named(&parsed, deny_set).is_empty(),
        Err(_) => false,
    }
}

/// The process-wide registry the search handler shares runs through.
pub(crate) fn searches() -> &'static InFlight<nanosiem_core::SearchResponse, nanosiem_core::SearchError> {
    static SEARCHES: std::sync::OnceLock<InFlight<nanosiem_core::SearchResponse, nanosiem_core::SearchError>> = std::sync::OnceLock::new();
    SEARCHES.get_or_init(InFlight::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::SearchResultCache;
    use nanosiem_core::auth::ScopeSet;
    use nanosiem_core::search::SearchTenantScope;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn request(query: &str) -> nanosiem_core::SearchRequest {
        serde_json::from_value(serde_json::json!({
            "query": query,
            "time_range": {"start": "2026-10-26T00:00:00Z", "end": "2026-10-27T00:00:00Z"},
            "limit": 500, "skip_histogram": true, "skip_field_stats": true, "use_cache": false,
        }))
        .unwrap()
    }

    fn no_shared_failure(_: &()) -> Option<()> {
        None
    }

    fn shared(tenant: u128) -> SearchTenantScope {
        SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(tenant))
    }

    /// The bakeoff shape: 16 agents fire the same hunt at once; it runs
    /// once and all 16 get its result, the 15 followers without a slot.
    #[tokio::test]
    async fn sixteen_identical_agent_hunts_run_once() {
        let registry = Arc::new(InFlight::<String, ()>::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let (release, released) = watch::channel(false);
        let hunt = "class_uid=1007 | stats count as c by process.name | sort -c | head 20";
        let mut agents = Vec::new();
        for agent in 0..16 {
            // Each agent types the hunt slightly differently; the
            // normalized identity is the same.
            let query = if agent % 2 == 0 { format!("  {hunt} ") } else { hunt.replace(" | ", "  |  ") };
            let key = SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), &request(&query), &ScopeSet::default(), None, b"");
            let (registry, runs, released) = (registry.clone(), runs.clone(), released.clone());
            agents.push(tokio::spawn(async move {
                registry
                    .run(&key, || {
                        let (runs, mut released) = (runs.clone(), released.clone());
                        async move {
                            runs.fetch_add(1, Ordering::SeqCst);
                            while !*released.borrow_and_update() {
                                released.changed().await.unwrap();
                            }
                            Ok::<_, ()>("rows".to_string())
                        }
                    }, no_shared_failure)
                    .await
            }));
        }
        // Let every agent arrive while the leader's run is in flight.
        while registry.len() == 0 || runs.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        release.send(true).unwrap();
        let mut leaders = 0;
        for agent in agents {
            let (result, role) = agent.await.unwrap();
            assert_eq!(result.unwrap(), "rows");
            leaders += usize::from(role == Role::Leader);
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "16 identical in-flight hunts ran once");
        assert_eq!(leaders, 1);
        assert_eq!(registry.len(), 0, "a finished run is forgotten at once");
    }

    /// Strictly per tenant: the same hunt from two tenants never shares a
    /// run, even with identical everything else.
    #[test]
    fn identity_is_per_tenant() {
        let request = request("dst_endpoint.ip=10.0.0.1 | stats count");
        let generation = None;
        let a = SearchResultCache::inflight_key_for(shared(0xa), &request, &ScopeSet::default(), generation, b"");
        let b = SearchResultCache::inflight_key_for(shared(0xb), &request, &ScopeSet::default(), generation, b"");
        let dedicated = SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), &request, &ScopeSet::default(), generation, b"");
        assert_ne!(a, b);
        assert_ne!(a, dedicated);
        assert_ne!(b, dedicated);
    }

    /// Two tenants running the same hunt at once each run their own.
    #[tokio::test]
    async fn concurrent_tenants_never_share_a_run() {
        let registry = InFlight::<String, ()>::default();
        let request = request("dst_endpoint.ip=10.0.0.1 | stats count");
        let key_a = SearchResultCache::inflight_key_for(shared(0xa), &request, &ScopeSet::default(), None, b"");
        let key_b = SearchResultCache::inflight_key_for(shared(0xb), &request, &ScopeSet::default(), None, b"");
        let (release, released) = watch::channel(false);
        let lead = |tenant: &'static str| {
            let released = released.clone();
            move || {
                let mut released = released.clone();
                async move {
                    while !*released.borrow_and_update() {
                        released.changed().await.unwrap();
                    }
                    Ok::<_, ()>(tenant.to_string())
                }
            }
        };
        let a = registry.run(&key_a, lead("rows-of-a"), no_shared_failure);
        let b = registry.run(&key_b, lead("rows-of-b"), no_shared_failure);
        let both = async {
            tokio::task::yield_now().await;
            release.send(true).unwrap();
        };
        let ((a, role_a), (b, role_b), ()) = tokio::join!(a, b, both);
        assert_eq!((a.unwrap(), role_a), ("rows-of-a".to_string(), Role::Leader));
        assert_eq!((b.unwrap(), role_b), ("rows-of-b".to_string(), Role::Leader), "tenant B never received A's rows");
    }

    /// RBAC scope: a caller with a different effective deny set (source or
    /// artifact) never shares a run with one who can see more.
    #[test]
    fn identity_includes_the_effective_rbac_scope() {
        let request = request("* | stats count by metadata.log_source");
        let open = ScopeSet::default();
        let restricted = ScopeSet::from_denied(["insider_threat".to_string()].into());
        let open_key = SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), &request, &open, None, b"");
        let restricted_key = SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), &request, &restricted, None, b"");
        assert_ne!(open_key, restricted_key);
    }

    /// The identity covers every result-shaping field.
    #[test]
    fn identity_covers_time_bounds_limit_and_shape() {
        let base = request("class_uid=4001 | timechart span=1m count");
        let key = |r: &nanosiem_core::SearchRequest| SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), r, &ScopeSet::default(), None, b"");
        let mut later = base.clone();
        later.time_range.end += chrono::Duration::seconds(1);
        let mut limit = base.clone();
        limit.limit = Some(100);
        let mut offset = base.clone();
        offset.offset = Some(500);
        let mut sql = base.clone();
        sql.include_sql = Some(true);
        let mut table = base.clone();
        table.table_view = true;
        let mut histogram = base.clone();
        histogram.skip_histogram = false;
        let mut dataset = base.clone();
        dataset.dataset = Some("spans".into());
        let mut query = base.clone();
        query.query = "class_uid=4001 | timechart span=5m count".into();
        // `use_cache: true` lets ClickHouse answer from its query cache: a
        // fresh (`false`) caller never follows such a run.
        let mut ch_cache = base.clone();
        ch_cache.use_cache = true;
        for variant in [later, limit, offset, sql, table, histogram, dataset, query, ch_cache] {
            assert_ne!(key(&base), key(&variant));
        }
        // ...and only those: the request id does not change the result.
        let mut agent = base.clone();
        agent.request_id = Some("agent-7".into());
        assert_eq!(key(&base), key(&agent));
        // The caller's authority fingerprint is part of the identity.
        let authority = |bytes: &[u8]| SearchResultCache::inflight_key_for(SearchTenantScope::dedicated(), &base, &ScopeSet::default(), None, bytes);
        assert_ne!(authority(b"ent=Some(7)"), authority(b"ent=Some(8)"));
    }

    /// A failure the query itself determines (a budget, a parse error)
    /// reaches every follower at once: 8 identical requests run the search
    /// ONCE, not one after another.
    #[tokio::test]
    async fn a_query_determined_failure_is_shared_not_rerun_serially() {
        let registry = Arc::new(InFlight::<String, nanosiem_core::SearchError>::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let (release, released) = watch::channel(false);
        let key = "inflight:test-shared-failure".to_string();
        let mut callers = Vec::new();
        for _ in 0..8 {
            let (registry, runs, released, key) = (registry.clone(), runs.clone(), released.clone(), key.clone());
            callers.push(tokio::spawn(async move {
                registry
                    .run(&key, || {
                        let (runs, mut released) = (runs.clone(), released.clone());
                        async move {
                            runs.fetch_add(1, Ordering::SeqCst);
                            while !*released.borrow_and_update() {
                                released.changed().await.unwrap();
                            }
                            Err::<String, _>(nanosiem_core::SearchError::ResourceExhausted("memory".into()))
                        }
                    }, query_determined_failure)
                    .await
            }));
        }
        while runs.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        release.send(true).unwrap();
        for caller in callers {
            let (result, _) = caller.await.unwrap();
            assert!(matches!(result, Err(nanosiem_core::SearchError::ResourceExhausted(kind)) if kind == "memory"));
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "followers received the leader's failure");
        assert_eq!(registry.len(), 0);
    }

    /// Caller- or moment-specific failures are never copied to followers.
    #[test]
    fn only_query_determined_failures_are_shared() {
        use nanosiem_core::SearchError as E;
        assert!(query_determined_failure(&E::Timeout(30_000)).is_some());
        assert!(query_determined_failure(&E::ParseError("x".into())).is_some());
        assert!(query_determined_failure(&E::AdmissionDenied("user limit".into())).is_none(), "the leader's admission is its own");
        assert!(query_determined_failure(&E::AdmissionBackendUnavailable).is_none());
        assert!(query_determined_failure(&E::Cancelled).is_none(), "a DELETE of the leader is not the follower's");
        assert!(query_determined_failure(&E::ServiceUnavailable("blip".into())).is_none());
    }

    /// A cancelled leader (client gone, escalation, DELETE) never fails its
    /// followers: one takes over and runs the search.
    #[tokio::test]
    async fn follower_takes_over_from_a_cancelled_leader() {
        let registry = Arc::new(InFlight::<String, ()>::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let key = "inflight:test-cancel".to_string();
        let leader = {
            let (registry, runs, key) = (registry.clone(), runs.clone(), key.clone());
            tokio::spawn(async move {
                registry
                    .run(&key, || {
                        runs.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<Result<String, ()>>()
                    }, no_shared_failure)
                    .await
            })
        };
        while runs.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let follower = {
            let (registry, runs, key) = (registry.clone(), runs.clone(), key.clone());
            tokio::spawn(async move {
                registry
                    .run(&key, || {
                        runs.fetch_add(1, Ordering::SeqCst);
                        async { Ok::<_, ()>("fresh".to_string()) }
                    }, no_shared_failure)
                    .await
            })
        };
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(!follower.is_finished(), "the follower waits on the leader");
        leader.abort();
        let (result, role) = tokio::time::timeout(std::time::Duration::from_secs(5), follower).await.unwrap().unwrap();
        assert_eq!(result.unwrap(), "fresh");
        assert_eq!(role, Role::Leader, "the follower took over");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(registry.len(), 0);
    }

    /// A failed leader run is retried by a follower, not propagated.
    #[tokio::test]
    async fn follower_takes_over_from_a_failed_leader() {
        let registry = Arc::new(InFlight::<String, &'static str>::default());
        let (fail, failing) = watch::channel(false);
        let key = "inflight:test-error".to_string();
        let leader = {
            let (registry, key, failing) = (registry.clone(), key.clone(), failing.clone());
            tokio::spawn(async move {
                registry
                    .run(&key, || {
                        let mut failing = failing.clone();
                        async move {
                            while !*failing.borrow_and_update() {
                                failing.changed().await.unwrap();
                            }
                            Err::<String, _>("cell unavailable")
                        }
                    }, |_| None)
                    .await
            })
        };
        while registry.len() == 0 {
            tokio::task::yield_now().await;
        }
        let follower = {
            let (registry, key) = (registry.clone(), key.clone());
            tokio::spawn(async move { registry.run(&key, || async { Ok::<_, &'static str>("retried".to_string()) }, |_| None).await })
        };
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        fail.send(true).unwrap();
        let (leader_result, _) = leader.await.unwrap();
        assert_eq!(leader_result.unwrap_err(), "cell unavailable");
        let (result, role) = follower.await.unwrap();
        assert_eq!((result.unwrap(), role), ("retried".to_string(), Role::Leader));
    }

    #[test]
    fn eligibility_keeps_caller_dependent_runs_apart() {
        let none = std::collections::BTreeSet::new();
        assert!(share_eligible("class_uid=1007 | stats count", &none, false, false, false, false, false));
        assert!(!share_eligible("class_uid=1007", &none, false, false, true, false, false), "debug runs never share");
        assert!(!share_eligible("class_uid=1007", &none, false, false, false, true, false), "progressive views never share");
        assert!(!share_eligible("class_uid=1007", &none, true, false, false, false, false), "shared tenant needs its generation");
        assert!(share_eligible("class_uid=1007", &none, true, true, false, false, false));
        assert!(!share_eligible("class_uid=1007", &none, true, true, false, false, true), "a request-bound risk view never shares");
        assert!(!share_eligible("* | lookup assets ip as src_ip", &none, false, false, false, false, false), "lookups read live state");
        assert!(!share_eligible(r#"* | ai "summarize""#, &none, false, false, false, false, false), "| ai is billed per member");
        let denied: std::collections::BTreeSet<String> = ["insider_threat".to_string()].into();
        assert!(share_eligible("class_uid=1007", &denied, false, false, false, false, false));
        assert!(
            !share_eligible("metadata.log_source=insider_threat", &denied, false, false, false, false, false),
            "a probe for a hidden source leads its own (audited) run"
        );
    }
}
