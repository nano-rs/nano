// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::cache::SearchResultCache;
use nanosiem_core::auth::ScopeSet;
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
        let key = SearchResultCache::inflight_key_for(&request(&query), &ScopeSet::default(), b"");
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

/// RBAC scope: a caller with a different effective deny set (source or
/// artifact) never shares a run with one who can see more.
#[test]
fn identity_includes_the_effective_rbac_scope() {
    let request = request("* | stats count by metadata.log_source");
    let open = ScopeSet::default();
    let restricted = ScopeSet::from_denied(["insider_threat".to_string()].into());
    let open_key = SearchResultCache::inflight_key_for(&request, &open, b"");
    let restricted_key = SearchResultCache::inflight_key_for(&request, &restricted, b"");
    assert_ne!(open_key, restricted_key);
}

/// The identity covers every result-shaping field.
#[test]
fn identity_covers_time_bounds_limit_and_shape() {
    let base = request("class_uid=4001 | timechart span=1m count");
    let key = |r: &nanosiem_core::SearchRequest| SearchResultCache::inflight_key_for(r, &ScopeSet::default(), b"");
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
    let authority = |bytes: &[u8]| SearchResultCache::inflight_key_for(&base, &ScopeSet::default(), bytes);
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
                        Err::<String, _>(nanosiem_core::SearchError::Timeout(30_000))
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
        assert!(matches!(result, Err(nanosiem_core::SearchError::Timeout(30_000))));
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
    assert!(query_determined_failure(&E::Cancelled).is_none(), "a DELETE of the leader is not the follower's");
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
    assert!(share_eligible("class_uid=1007 | stats count", &none));
    assert!(!share_eligible("* | lookup assets ip as src_ip", &none), "lookups read live state");
    assert!(!share_eligible(r#"* | ai "summarize""#, &none), "| ai is billed per member");
    let denied: std::collections::BTreeSet<String> = ["insider_threat".to_string()].into();
    assert!(share_eligible("class_uid=1007", &denied));
    assert!(
        !share_eligible("metadata.log_source=insider_threat", &denied),
        "a probe for a hidden source leads its own (audited) run"
    );
}

/// NAN-4928 RBAC: a lower-privileged caller (a narrower effective scope, or
/// the audit gate) never shares a leader's run computed under a wider scope:
/// the two searches run separately and each gets its own rows.
#[tokio::test]
async fn a_restricted_caller_never_follows_a_wider_scopes_run() {
    let registry = Arc::new(InFlight::<String, ()>::default());
    let request = request("class_uid=1007 | stats count by metadata.log_source");
    let analyst = ScopeSet::default();
    let restricted = ScopeSet::from_denied(["insider_threat".to_string()].into());
    let key_wide = SearchResultCache::inflight_key_for(&request, &analyst, b"pri=Interactive");
    let key_narrow = SearchResultCache::inflight_key_for(&request, &restricted, b"pri=Interactive");
    assert_ne!(key_wide, key_narrow);
    let (release, released) = watch::channel(false);
    let lead = |rows: &'static str| {
        let released = released.clone();
        move || {
            let mut released = released.clone();
            async move {
                while !*released.borrow_and_update() {
                    released.changed().await.unwrap();
                }
                Ok::<_, ()>(rows.to_string())
            }
        }
    };
    let wide = registry.run(&key_wide, lead("rows incl. insider_threat"), no_shared_failure);
    let narrow = registry.run(&key_narrow, lead("rows without insider_threat"), no_shared_failure);
    let go = async {
        tokio::task::yield_now().await;
        release.send(true).unwrap();
    };
    let ((wide, wide_role), (narrow, narrow_role), ()) = tokio::join!(wide, narrow, go);
    assert_eq!((wide.unwrap(), wide_role), ("rows incl. insider_threat".to_string(), Role::Leader));
    assert_eq!(
        (narrow.unwrap(), narrow_role),
        ("rows without insider_threat".to_string(), Role::Leader),
        "the restricted caller ran its own search"
    );
}

/// NAN-4928 review P2: a query with relative time modifiers resolves its
/// window per request at execution, so it never shares a run; a probe of a
/// hidden source never takes a fast path.
#[test]
fn relative_time_modifiers_and_hidden_source_probes_never_share() {
    let none = std::collections::BTreeSet::new();
    assert!(!share_eligible("* earliest=-1s latest=now | stats count", &none));
    assert!(share_eligible("* | stats count", &none));
    let denied: std::collections::BTreeSet<String> = ["secret".to_string(), "audit".to_string()].into();
    assert!(names_denied_source("(source_type=secret OR source_type=allowed)", &denied));
    assert!(names_denied_source("source_type=audit", &denied));
    assert!(!names_denied_source("source_type=allowed", &denied));
    assert!(names_denied_source("| | not a query", &denied), "unparsable is conservative");
    assert!(!names_denied_source("source_type=secret", &none));
}
