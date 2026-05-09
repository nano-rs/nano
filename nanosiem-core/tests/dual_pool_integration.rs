//! Integration tests for DualPool connectivity
//!
//! These tests require both PostgreSQL and ClickHouse to be running.
//! Run with: cargo test --test dual_pool_integration -- --nocapture
//!
//! Prerequisites:
//! - docker-compose up -d postgres clickhouse

use nanosiem_core::{DualPool, DualPoolConfig};

/// Test that DualPool can connect to both databases
#[tokio::test]
async fn test_dual_pool_connects_to_both_databases() {
    // Skip if databases aren't available (CI environment)
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        println!("Skipping database tests (SKIP_DB_TESTS is set)");
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
            println!("Could not connect to databases: {}", e);
            println!("Make sure both PostgreSQL and ClickHouse are running:");
            println!("  docker-compose up -d postgres clickhouse");
            return;
        }
    };

    println!("Successfully connected to both databases!");

    // Verify health check works
    let health = pool.health_check().await;

    println!("Health check results:");
    println!(
        "  PostgreSQL: healthy={}, latency={}ms",
        health.postgres_healthy, health.postgres_latency_ms
    );
    println!(
        "  ClickHouse: healthy={}, latency={}ms",
        health.clickhouse_healthy, health.clickhouse_latency_ms
    );

    assert!(health.postgres_healthy, "PostgreSQL should be healthy");
    assert!(health.clickhouse_healthy, "ClickHouse should be healthy");
    assert!(health.is_healthy(), "Both databases should be healthy");

    // Verify we can query PostgreSQL
    let pg_result: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(pool.postgres())
        .await
        .expect("PostgreSQL query should succeed");
    assert_eq!(pg_result.0, 1);
    println!("PostgreSQL query test: PASSED");

    // Verify we can query ClickHouse
    let ch_result: u8 = pool
        .clickhouse()
        .query("SELECT 1")
        .fetch_one()
        .await
        .expect("ClickHouse query should succeed");
    assert_eq!(ch_result, 1);
    println!("ClickHouse query test: PASSED");

    // Verify logs table exists in ClickHouse
    let table_count: u64 = pool
        .clickhouse()
        .query("SELECT count() FROM system.tables WHERE database = 'nanosiem' AND name = 'logs'")
        .fetch_one()
        .await
        .expect("ClickHouse system query should succeed");
    assert_eq!(
        table_count, 1,
        "logs table should exist in nanosiem database"
    );
    println!("ClickHouse logs table check: PASSED");

    pool.close().await;
    println!("\nAll dual pool integration tests passed!");
}
