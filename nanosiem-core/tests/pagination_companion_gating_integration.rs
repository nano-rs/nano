// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1645 (finding 3.5): pagination companion gating regression test.
//!
//! Page flips (offset > 0) must NOT re-run the count + histogram companion
//! queries — both are page-invariant and page 1 already delivered them. This
//! test observes the gate through the response shape:
//!
//!   - offset = 0: `histogram` is `Some` (companion ran) and `total_count`
//!     is the real count (0 for a no-match query).
//!   - offset > 0 with `skip_histogram` NOT set: `histogram` is `None`
//!     (spawn was offset-gated) and `total_count` is the paged estimate
//!     `offset + returned` — NOT the real count, proving the count companion
//!     did not run (a live companion would have reported 0 for the no-match
//!     sentinel query).
//!
//! Requires PostgreSQL + ClickHouse running (docker-compose up -d). Skips
//! gracefully (returns) when they aren't reachable so it's safe in CI without
//! a stack; the assertions only run when connected.

use chrono::{Duration, Utc};
use nanosiem_core::{DualPool, DualPoolConfig, SearchRequest, SearchService};

/// A keyword that matches nothing, so the exact count is provably 0 — any
/// nonzero page-N total must therefore be the estimate, not a companion count.
const NO_MATCH_SENTINEL: &str = "zzz_nan1645_no_match_sentinel";

fn request(query: &str, offset: usize) -> SearchRequest {
    let start = Utc::now() - Duration::hours(24);
    let end = Utc::now() + Duration::hours(1);
    serde_json::from_value(serde_json::json!({
        "query": query,
        "time_range": { "start": start, "end": end },
        "limit": 100,
        "offset": offset,
    }))
    .expect("SearchRequest deserializes from minimal fields")
}

async fn connect() -> Option<DualPool> {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return None;
    }
    let config = DualPoolConfig::with_auth(
        "postgres://nanosiem:nanosiem@localhost:5432/nanosiem",
        "http://localhost:8123",
        "nanosiem",
        "nanosiem",
        "nanosiem",
    );
    match DualPool::new(&config).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("Could not connect to databases ({e}); skipping. Run: docker-compose up -d");
            None
        }
    }
}

#[tokio::test]
async fn first_page_runs_companions() {
    let Some(pool) = connect().await else {
        return;
    };
    let svc = SearchService::with_dual_pool(&pool);

    let resp = svc
        .search(request(NO_MATCH_SENTINEL, 0))
        .await
        .expect("offset=0 search should succeed");

    assert!(
        resp.histogram.is_some(),
        "offset=0 must run the histogram companion (skip_histogram was not set)"
    );
    assert_eq!(
        resp.total_count, 0,
        "offset=0 must report the companion's exact count (sentinel matches nothing)"
    );
}

#[tokio::test]
async fn page_flips_skip_companions() {
    let Some(pool) = connect().await else {
        return;
    };
    let svc = SearchService::with_dual_pool(&pool);

    let offset = 200usize;
    let resp = svc
        .search(request(NO_MATCH_SENTINEL, offset))
        .await
        .expect("offset>0 search should succeed");

    assert!(
        resp.histogram.is_none(),
        "offset>0 must NOT spawn the histogram companion even without skip_histogram"
    );
    assert!(
        resp.results.is_empty(),
        "sentinel query must match nothing at any offset"
    );
    // The paged estimate is offset + returned (= offset here). A live count
    // companion would have reported 0 — the estimate proves it was skipped.
    assert_eq!(
        resp.total_count, offset as u64,
        "offset>0 must report the paged estimate, not a companion recount"
    );
}
