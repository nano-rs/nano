//! End-to-end smoke test for the per-source_type log telemetry rollup (NAN-733).
//!
//! Boots against a local docker-compose stack, ensures migration 116 has been
//! applied (prerequisite — the test does not run migrations itself; rely on
//! the API binary's startup migrator or `cargo run --bin clickhouse_migrator`),
//! inserts a handful of synthetic rows into `nanosiem.logs`, waits for the
//! materialized view to fire, and asserts the rollup totals match what we just
//! inserted. Catches column-name typos and `lower(source_type)` drift that
//! unit tests can't cover.
//!
//! Skipped when `SKIP_DB_TESTS` is set (matches `dual_pool_integration.rs`).
//!
//! Run with: `cargo test --test log_telemetry_rollup_smoke -- --nocapture`

use chrono::Utc;
use nanosiem_core::db::TableNames;
use nanosiem_core::log_telemetry::LogTelemetryService;
use nanosiem_core::{DualPool, DualPoolConfig};
use uuid::Uuid;

#[tokio::test]
async fn rollup_matches_raw_logs_for_inserted_rows() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        println!("Skipping (SKIP_DB_TESTS is set)");
        return;
    }

    let config = DualPoolConfig::with_auth(
        "postgres://nanosiem:nanosiem@localhost:5432/nanosiem",
        "http://localhost:8123",
        "nanosiem",
        "nanosiem",
        "nanosiem",
    );
    let pool = match DualPool::new(&config).await {
        Ok(p) => p,
        Err(e) => {
            println!("Could not connect to databases: {e}");
            println!("Bring up the stack with: docker-compose up -d postgres clickhouse");
            return;
        }
    };

    let ch = pool.clickhouse();

    // Sanity: rollup table must exist (migration 116 applied).
    let exists: u64 = ch
        .query(
            "SELECT count() FROM system.tables \
             WHERE database = 'nanosiem' AND name = 'logs_per_source_5m'",
        )
        .fetch_one()
        .await
        .expect("system.tables query should succeed");
    if exists == 0 {
        panic!(
            "logs_per_source_5m table does not exist — apply migration 116 \
             before running this test (e.g., start the API once or run the \
             clickhouse_migrator binary)."
        );
    }

    // Use a unique source_type per run so we don't collide with other test
    // data or production source_types if anyone runs this against a shared CH.
    let unique = format!("nan733_smoke_{}", Uuid::new_v4().simple());
    let now = Utc::now();

    // Insert 5 synthetic rows spanning a single 5-minute bucket.
    let insert_sql = format!(
        "INSERT INTO nanosiem.logs (id, timestamp, source_type, message, metadata) \
         VALUES \
           (generateUUIDv4(), now(), '{st}', 'event one', '{{}}'),\
           (generateUUIDv4(), now(), '{st}', 'event two', '{{}}'),\
           (generateUUIDv4(), now(), '{st}', 'event three', '{{}}'),\
           (generateUUIDv4(), now(), '{st}', 'event four', '{{}}'),\
           (generateUUIDv4(), now(), '{st}', 'event five', '{{}}')",
        st = unique
    );
    ch.query(&insert_sql)
        .execute()
        .await
        .expect("insert into logs should succeed");

    // Read back through the service the same way handlers will. Poll up to
    // 10 s for the MV to fire — the MV runs synchronously on insert but the
    // AggregatingMergeTree target may buffer briefly before the row is
    // visible. Polling avoids the flakiness of a fixed sleep.
    let svc = LogTelemetryService::new(ch.clone(), TableNames::new(pool.is_clustered()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let row = loop {
        let stats = svc
            .stats_by_source_type(&[unique.clone()], 1)
            .await
            .expect("rollup read should succeed");
        if let Some(row) = stats.get(&unique).cloned() {
            break row;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "rollup never produced a row for {unique} within 10s; \
                 got keys this cycle: {:?}",
                stats.keys().collect::<Vec<_>>()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    assert_eq!(row.events, 5, "events count mismatch: {row:?}");
    assert!(row.bytes > 0, "bytes should be non-zero (we wrote messages)");
    assert!(
        row.last_event_at.is_some(),
        "last_event_at should be populated"
    );
    let last = row.last_event_at.unwrap();
    let drift = (last - now).num_seconds().abs();
    assert!(
        drift < 60,
        "last_event_at drift > 60s: now={now}, last={last}, drift={drift}s"
    );

    println!("Rollup parity check passed: {} events, {} bytes", row.events, row.bytes);

    // Cleanup: delete the synthetic rows from `logs`. The rollup row will age
    // out via TTL within 7 days; we don't bother with explicit ALTER DELETE
    // there because the rollup uses LowCardinality(String) which makes per-key
    // mutations expensive, and a single bucket of test data is harmless.
    let _ = ch
        .query(&format!(
            "ALTER TABLE nanosiem.logs DELETE WHERE source_type = '{unique}'"
        ))
        .execute()
        .await;

    pool.close().await;
}
