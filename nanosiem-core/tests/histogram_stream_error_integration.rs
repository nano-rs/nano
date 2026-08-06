// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1436 — forced-error regression test for the NAN-1429 (E5) histogram
//! read-loop fix, against a live ClickHouse.
//!
//! The pre-fix loop in `execute_clickhouse_histogram_query` was
//! `while let Ok(Some(chunk)) = cursor.next().await`, which treated ANY
//! stream `Err` — including a before-first-block error on the very first
//! `cursor.next()` — as end-of-stream. The empty byte buffer then parsed to
//! zero buckets, `fill_histogram_gaps` zero-filled the whole range, and the
//! caller received `Ok(<all-zero timeline>)`: a confidently wrong histogram
//! rendered next to real result rows. The fix propagates the error.
//!
//! This test drives the REAL fixed loop (service-constructed cursor against a
//! live CH) into a guaranteed stream error and asserts the contract:
//! the histogram call returns `Err`, NOT `Ok` with empty/zero-filled buckets.
//!
//! Forcing the error: the per-query settings seam (`active_ch_settings`, the
//! same one the admission-controlled path uses, NAN-1428) with
//! `max_memory_usage = 1` byte (+ `max_execution_time = 1s` belt-and-braces).
//! `ClickHouseQuerySettings.max_execution_time` is `u32` seconds, so a
//! fractional "absurdly low" timeout can't be expressed; the 1-byte memory cap
//! gives a deterministic sub-second failure independent of local data volume
//! (verified empirically: CH 26.4 rejects the GROUP BY scan with Code 241
//! MEMORY_LIMIT_EXCEEDED before the first block). The mechanism doesn't
//! matter — the contract under test is "stream error ⇒ Err", which is exactly
//! the path a mid-stream execution-time cap takes.
//!
//! Red-against-pre-fix proof: temporarily reverting the loop to the old
//! `while let Ok(Some(chunk))` shape makes this test fail with
//! `Ok` + 337 all-zero buckets (documented in the NAN-1436 PR), confirming it
//! guards the actual regression.
//!
//! `#[ignore]`-gated (needs live PG + CH). Run against the local dev stack:
//!   docker-compose up -d postgres clickhouse
//!   cargo test -p nanosiem-core --test histogram_stream_error_integration -- --ignored --nocapture

use nanosiem_core::search::ClickHouseQuerySettings;
use nanosiem_core::{DualPool, DualPoolConfig, SearchService, TimeRangeInput};

fn pg_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".into())
}
fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_TEST_USER").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_TEST_PASSWORD").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_db() -> String {
    std::env::var("CLICKHOUSE_TEST_DB").unwrap_or_else(|_| "nanosiem".into())
}

#[tokio::test]
#[ignore = "needs live PostgreSQL + ClickHouse; run with --ignored"]
async fn histogram_stream_error_returns_err_not_zero_filled_ok() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }

    let config = DualPoolConfig::with_auth(&pg_url(), &ch_url(), &ch_user(), &ch_pass(), &ch_db());
    let pool = match DualPool::new(&config).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Skipping: databases not reachable ({e}). Start them with: \
                 docker-compose up -d postgres clickhouse"
            );
            return;
        }
    };

    // The test constructs its OWN service inside the test process — it does
    // not touch the running dev stack (:3000/:3002).
    let mut service = SearchService::with_dual_pool(&pool);

    let now = chrono::Utc::now();
    let time_range = TimeRangeInput::new(now - chrono::Duration::days(7), now);

    // Force a guaranteed ClickHouse-side failure on the histogram companion:
    // a 1-byte memory cap kills the GROUP BY scan before the first block
    // (Code 241), i.e. the exact "before-first-block stream error" the old
    // `while let Ok(Some(chunk))` loop silently swallowed into Ok(empty).
    let lethal_settings = ClickHouseQuerySettings {
        max_execution_time: 1,
        max_memory_usage_bytes: Some(1),
        max_threads: 1,
        priority: 1,
        queue_max_wait_ms: 5_000,
    };

    let result = service
        .histogram_with_forced_ch_settings("*", &time_range, lethal_settings)
        .await;

    match result {
        Err(e) => {
            eprintln!("Contract holds: histogram stream error propagated as Err: {e}");
        }
        Ok(buckets) => {
            // This is the pre-NAN-1429 failure shape: the stream error was
            // swallowed, the empty response parsed to zero buckets, and
            // fill_histogram_gaps fabricated an all-zero timeline.
            let total: u64 = buckets.iter().map(|b| b.count).sum();
            panic!(
                "REGRESSION (NAN-1429/E5): histogram returned Ok with {} bucket(s) \
                 (total count {total}) despite a forced ClickHouse stream error — \
                 the read loop is swallowing cursor errors into a zero-filled \
                 timeline again",
                buckets.len(),
            );
        }
    }

    // Sanity: the same path with sane settings must still succeed, proving the
    // Err above came from the forced settings, not a broken happy path.
    let sane_settings = ClickHouseQuerySettings {
        max_execution_time: 60,
        max_memory_usage_bytes: Some(2 * 1024 * 1024 * 1024),
        max_threads: 2,
        priority: 1,
        queue_max_wait_ms: 5_000,
    };
    let ok = service
        .histogram_with_forced_ch_settings("*", &time_range, sane_settings)
        .await
        .expect("histogram with sane settings should succeed against local CH");
    eprintln!(
        "Happy path intact: {} bucket(s) with sane settings",
        ok.len()
    );

    pool.close().await;
}
