// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2096 — live `RedisJobStore` proofs that an async search result stops
//! being readable once the caller's source scope narrows.
//!
//! The unit tests in `search::jobs` cover the predicate and the in-memory store.
//! These cover the half that only a real server exercises: the hash round-trip
//! (`scope_deny` written on create, decoded on read), the `Vec<Option<String>>`
//! HMGET decode that must tolerate a nil `scope_deny` on a pre-upgrade job, and
//! `list_all` / `active_count` behavior against the Redis implementation.
//!
//! Run with a live Redis/Dragonfly:
//!   `NANOSIEM_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p nanosiem-core \
//!    --test search_job_scope_revocation_integration -- --ignored`

use std::collections::BTreeSet;

use chrono::Utc;
use nanosiem_core::auth::ScopeSet;
use nanosiem_core::search::{
    QueryPriority, RedisJobStore, SearchJobStore, SearchRequest, SearchResponse,
};
use nanosiem_core::TimeRangeInput;

fn redis_url() -> String {
    std::env::var("NANOSIEM_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn deny(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn request(query: &str) -> SearchRequest {
    SearchRequest {
        query: query.to_string(),
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
        async_mode: true,
        priority: None,
        dataset: None,
    }
}

async fn store() -> RedisJobStore {
    RedisJobStore::connect(&redis_url())
        .await
        .expect("live Redis/Dragonfly required — set NANOSIEM_TEST_REDIS_URL")
}

/// The reported repro end-to-end against Redis: a job runs while a source is
/// visible, the source is then restricted, and the completed result must stop
/// being readable — while an unchanged scope still reads it.
#[tokio::test]
#[ignore = "requires a live Redis/Dragonfly (NANOSIEM_TEST_REDIS_URL); run with --ignored"]
async fn redis_job_result_hidden_after_source_restriction() {
    let store = store().await;
    let user = uuid::Uuid::now_v7();
    let submitted = ScopeSet::from_denied(deny(&["audit"]));

    let job_id = store
        .create_queued(
            request("source_type=\"windows_sysmon\" | head 5"),
            user,
            QueryPriority::Interactive,
            &submitted,
        )
        .await
        .expect("create job");

    store.complete(&job_id, SearchResponse::empty()).await;

    let job = store.get(&job_id).await.expect("job round-trips");
    // The stamp survived the Redis hash round-trip — not `None`, which would
    // make this test pass for the wrong reason (unknown provenance also hides).
    assert_eq!(job.scope_deny.as_ref(), Some(&deny(&["audit"])));

    // Unchanged scope still reads the stored result.
    assert!(job.result_visible_under(&deny(&["audit"])));
    assert!(store.get_status(&job_id).await.is_some());

    // `windows_sysmon` restricted after the fact → the snapshot is hidden.
    assert!(!job.result_visible_under(&deny(&["audit", "windows_sysmon"])));

    store.remove(&job_id).await;
}

/// A job written by a pre-NAN-2096 node has no `scope_deny` hash field. Decoding
/// must not fail the WHOLE `get()` (redis-rs errors the entire conversion on a
/// nil slot when the target is `Vec<String>`), and the missing stamp must read
/// back as unknown → hidden from every restricted caller.
#[tokio::test]
#[ignore = "requires a live Redis/Dragonfly (NANOSIEM_TEST_REDIS_URL); run with --ignored"]
async fn redis_legacy_job_without_stamp_still_loads_and_fails_closed() {
    let store = store().await;
    let user = uuid::Uuid::now_v7();

    let job_id = store
        .create_queued(
            request("legacy"),
            user,
            QueryPriority::Interactive,
            &ScopeSet::from_denied(deny(&["audit"])),
        )
        .await
        .expect("create job");

    // Simulate the pre-upgrade row: drop just the stamp field.
    let client = redis::Client::open(redis_url()).expect("redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis conn");
    let _: i64 = redis::cmd("HDEL")
        .arg(format!("search:job:{}", job_id))
        .arg("scope_deny")
        .query_async(&mut conn)
        .await
        .expect("HDEL scope_deny");

    // `get()` must still return the job — ownership resolution and cancel
    // depend on it. Before the `Vec<Option<String>>` decode this returned None.
    let job = store.get(&job_id).await.expect("legacy job still loads");
    assert_eq!(job.user_id, Some(user));
    assert_eq!(job.scope_deny, None, "missing stamp decodes as unknown");

    // Unknown provenance is hidden from every restricted caller.
    assert!(!job.result_visible_under(&deny(&["audit"])));
    assert!(!job.result_visible_under(&deny(&["windows_sysmon"])));
    // …and readable only by a caller denied nothing at all.
    assert!(job.result_visible_under(&BTreeSet::new()));

    store.remove(&job_id).await;
}

/// `list_all` filters by the viewer's scope (NAN-2109 admin surface), while
/// `active_count` — internal admission accounting — must keep counting every
/// job. A regression here would silently under-count concurrency.
#[tokio::test]
#[ignore = "requires a live Redis/Dragonfly (NANOSIEM_TEST_REDIS_URL); run with --ignored"]
async fn redis_admin_list_filters_by_viewer_scope_without_breaking_counts() {
    let store = store().await;
    let marker = format!("nan2096_{}", uuid::Uuid::now_v7().simple());

    let wide = store
        .create_queued(
            request(&format!("{marker} wide")),
            uuid::Uuid::now_v7(),
            QueryPriority::Interactive,
            &ScopeSet::from_denied(deny(&["audit", "windows_sysmon"])),
        )
        .await
        .expect("create wide job");
    let narrow = store
        .create_queued(
            request(&format!("{marker} narrow")),
            uuid::Uuid::now_v7(),
            QueryPriority::Interactive,
            &ScopeSet::from_denied(deny(&["audit"])),
        )
        .await
        .expect("create narrow job");

    // A viewer denied `windows_sysmon` may only see the job that already
    // excluded it — the other one's query preview stays hidden.
    let viewer = deny(&["audit", "windows_sysmon"]);
    let visible: Vec<String> = store
        .list_all(&viewer)
        .await
        .into_iter()
        .map(|j| j.job_id)
        .collect();
    assert!(visible.contains(&wide));
    assert!(
        !visible.contains(&narrow),
        "admin list leaked a job whose result the poll route would refuse"
    );

    // Internal accounting is unfiltered: both jobs are queued and counted.
    let all: Vec<String> = store
        .list_all(&BTreeSet::new())
        .await
        .into_iter()
        .map(|j| j.job_id)
        .collect();
    assert!(all.contains(&wide) && all.contains(&narrow));
    assert!(
        store.active_count().await >= 2,
        "active_count must not be scope-filtered — admission control depends on it"
    );

    store.remove(&wide).await;
    store.remove(&narrow).await;
}
