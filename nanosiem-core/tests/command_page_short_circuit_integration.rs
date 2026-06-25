// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1560: command-page short-circuit regression test.
//!
//! `| service`, `| trace`, `| metric`, `| services` are PAGE directives that
//! short-circuit in `SearchService::search` BEFORE any ClickHouse scan: no
//! data query, no count companion, no histogram, no field stats. Each returns a
//! single synthetic marker row.
//!
//! This test is the empirical guard for that load-bearing placement (the count
//! companion is NOT display-type-gated, so a misplaced short-circuit would
//! silently scan logs). It asserts:
//!   - `total_count == 1` (the marker, not a real count)
//!   - `generated_sql.is_none()` (no SQL was generated → nothing scanned)
//!   - exactly one result row carrying the expected `_display_type` + entity
//!
//! Requires PostgreSQL + ClickHouse running (docker-compose up -d). Skips
//! gracefully (returns) when they aren't reachable so it's safe in CI without a
//! stack; the assertions only run when connected.

use chrono::{Duration, Utc};
use nanosiem_core::{DualPool, DualPoolConfig, SearchRequest, SearchService};

/// Build a SearchRequest from the minimal required fields; serde fills the rest
/// with their defaults (skip_histogram=false, dataset=None, etc.).
fn request(query: &str) -> SearchRequest {
    let start = Utc::now() - Duration::hours(24);
    let end = Utc::now() + Duration::hours(1);
    serde_json::from_value(serde_json::json!({
        "query": query,
        "time_range": { "start": start, "end": end },
        "include_sql": true,
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
async fn command_pages_short_circuit_without_scanning() {
    let Some(pool) = connect().await else {
        return;
    };
    let svc = SearchService::with_dual_pool(&pool);

    // (query, expected _display_type, expected entity key, expected entity value)
    let cases: &[(&str, &str, Option<(&str, &str)>)] = &[
        ("* | service checkout", "service", Some(("_service", "checkout"))),
        (
            "* | trace deadbeef00112233",
            "trace",
            Some(("_trace_id", "deadbeef00112233")),
        ),
        (
            "* | metric http.server.duration",
            "metric",
            Some(("_metric", "http.server.duration")),
        ),
        ("* | services", "services", None),
    ];

    for (query, expected_dt, entity) in cases {
        let resp = svc
            .search(request(query))
            .await
            .unwrap_or_else(|e| panic!("`{query}` should short-circuit, got error: {e}"));

        assert_eq!(
            resp.total_count, 1,
            "`{query}` must return the synthetic marker (total_count=1), not a scanned count"
        );
        assert!(
            resp.generated_sql.is_none(),
            "`{query}` must NOT generate SQL (proof of no scan); got {:?}",
            resp.generated_sql
        );
        assert_eq!(
            resp.results.len(),
            1,
            "`{query}` must yield exactly one marker row"
        );

        let marker = &resp.results[0];
        assert_eq!(
            marker.get("_display_type").and_then(|v| v.as_str()),
            Some(*expected_dt),
            "`{query}` marker _display_type mismatch"
        );
        if let Some((key, val)) = entity {
            assert_eq!(
                marker.get(*key).and_then(|v| v.as_str()),
                Some(*val),
                "`{query}` marker {key} mismatch"
            );
        }
    }
}
