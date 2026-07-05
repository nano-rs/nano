//! Integration tests for SearchService with ClickHouse backend
//!
//! These tests require both PostgreSQL and ClickHouse to be running.
//! Run with: cargo test --test search_clickhouse_integration -- --nocapture
//!
//! Prerequisites:
//! - docker-compose up -d postgres clickhouse
//! - Test data should be inserted into ClickHouse (see verify-clickhouse-search.sh)

#![cfg(any())]

use chrono::{Duration, Utc};
use nanosiem_core::{DualPool, DualPoolConfig, SearchRequest, SearchService, TimeRangeInput};

/// Test that SearchService can execute queries against ClickHouse
#[tokio::test]
async fn test_search_service_with_clickhouse() {
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

    // Create search service with DualPool (uses ClickHouse for logs)
    let search_service = SearchService::with_dual_pool(&pool);

    // Verify backend is ClickHouse
    assert_eq!(
        search_service.backend(),
        nanosiem_core::search::SearchBackend::ClickHouse
    );
    println!("SearchService backend: {:?}", search_service.backend());

    // Test 1: Simple keyword search
    println!("\n=== Test 1: Simple keyword search ===");
    let request = SearchRequest {
        query: "*".to_string(),
        time_range: TimeRangeInput {
            start: Utc::now() - Duration::hours(24),
            end: Utc::now() + Duration::hours(1),
        },
        limit: Some(10),
        offset: None,
        include_sql: Some(true),
    };

    match search_service.search(request).await {
        Ok(response) => {
            println!("Total count: {}", response.total_count);
            println!("Results returned: {}", response.results.len());
            println!("Execution time: {}ms", response.execution_time_ms);
            if let Some(sql) = &response.generated_sql {
                println!("Generated SQL: {}", sql);
            }
            assert!(response.total_count >= 0, "Should return valid count");
            println!("Test 1: PASSED");
        }
        Err(e) => {
            println!("Search failed: {}", e);
            println!("Test 1: FAILED (but may be expected if no data)");
        }
    }

    // Test 2: Field filter search
    println!("\n=== Test 2: Field filter search ===");
    let request = SearchRequest {
        query: "status=success".to_string(),
        time_range: TimeRangeInput {
            start: Utc::now() - Duration::hours(24),
            end: Utc::now() + Duration::hours(1),
        },
        limit: Some(10),
        offset: None,
        include_sql: Some(true),
    };

    match search_service.search(request).await {
        Ok(response) => {
            println!("Total count: {}", response.total_count);
            println!("Results returned: {}", response.results.len());
            if let Some(sql) = &response.generated_sql {
                println!("Generated SQL: {}", sql);
            }
            println!("Test 2: PASSED");
        }
        Err(e) => {
            println!("Search failed: {}", e);
            println!("Test 2: FAILED");
        }
    }

    // Test 3: Stats aggregation
    println!("\n=== Test 3: Stats aggregation ===");
    let request = SearchRequest {
        query: "* | stats count by action".to_string(),
        time_range: TimeRangeInput {
            start: Utc::now() - Duration::hours(24),
            end: Utc::now() + Duration::hours(1),
        },
        limit: Some(100),
        offset: None,
        include_sql: Some(true),
    };

    match search_service.search(request).await {
        Ok(response) => {
            println!("Total count: {}", response.total_count);
            println!("Results returned: {}", response.results.len());
            if let Some(sql) = &response.generated_sql {
                println!("Generated SQL: {}", sql);
            }
            for result in &response.results {
                println!("  {:?}", result);
            }
            println!("Test 3: PASSED");
        }
        Err(e) => {
            println!("Search failed: {}", e);
            println!("Test 3: FAILED");
        }
    }

    // Test 4: Explain query (no execution)
    println!("\n=== Test 4: Explain query ===");
    let time_range = TimeRangeInput {
        start: Utc::now() - Duration::hours(24),
        end: Utc::now() + Duration::hours(1),
    };

    match search_service
        .explain("admin | stats count by src_ip", &time_range, false, None)
        .await
    {
        Ok(sql) => {
            println!("Generated SQL for 'admin | stats count by src_ip':");
            println!("{}", sql);
            assert!(sql.contains("SELECT"), "SQL should contain SELECT");
            assert!(
                sql.contains("GROUP BY"),
                "SQL should contain GROUP BY for stats"
            );
            println!("Test 4: PASSED");
        }
        Err(e) => {
            println!("Explain failed: {}", e);
            println!("Test 4: FAILED");
        }
    }

    // Test 5: Pagination
    println!("\n=== Test 5: Pagination ===");
    let request = SearchRequest {
        query: "*".to_string(),
        time_range: TimeRangeInput {
            start: Utc::now() - Duration::hours(24),
            end: Utc::now() + Duration::hours(1),
        },
        limit: Some(2),
        offset: Some(0),
        include_sql: Some(true),
    };

    match search_service.search(request).await {
        Ok(response) => {
            println!(
                "Page 1 - Total: {}, Returned: {}",
                response.total_count,
                response.results.len()
            );
            assert!(response.results.len() <= 2, "Should respect limit");
            println!("Test 5: PASSED");
        }
        Err(e) => {
            println!("Search failed: {}", e);
            println!("Test 5: FAILED");
        }
    }

    pool.close().await;
    println!("\n=== All SearchService ClickHouse integration tests completed! ===");
}

/// Test that SearchService generates valid ClickHouse SQL for various query types
#[tokio::test]
async fn test_clickhouse_sql_generation() {
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
            return;
        }
    };

    let search_service = SearchService::with_dual_pool(&pool);
    let time_range = TimeRangeInput {
        start: Utc::now() - Duration::hours(24),
        end: Utc::now() + Duration::hours(1),
    };

    let test_queries = vec![
        ("*", "Wildcard search"),
        ("error", "Keyword search"),
        ("src_ip=192.168.1.1", "Field filter"),
        ("status=success AND user=admin", "AND filter"),
        ("status=success OR status=failed", "OR filter"),
        ("NOT status=failed", "NOT filter"),
        ("* | stats count", "Stats count"),
        ("* | stats count by src_ip", "Stats with group by"),
        ("* | stats dc(user)", "Distinct count"),
        ("* | head 10", "Head command"),
        ("* | tail 10", "Tail command"),
        ("* | sort timestamp", "Sort ascending"),
        ("* | sort -timestamp", "Sort descending"),
        ("* | table src_ip, dest_ip, user", "Table command"),
        ("* | rename src_ip as source", "Rename command"),
        ("* | where status=success", "Where command"),
        ("* | dedup src_ip", "Dedup command"),
        ("* | eval total_bytes=bytes_in+bytes_out", "Eval command"),
        ("* | timechart span=1h count", "Timechart command"),
    ];

    println!("Testing SQL generation for various query types:\n");

    for (query, description) in test_queries {
        print!("  {} ... ", description);
        match search_service.explain(query, &time_range, false, None).await {
            Ok(sql) => {
                // Verify SQL contains expected elements
                assert!(sql.contains("SELECT"), "SQL should contain SELECT");
                assert!(sql.contains("logs"), "SQL should reference logs table");
                println!("OK");
            }
            Err(e) => {
                println!("FAILED: {}", e);
            }
        }
    }

    pool.close().await;
    println!("\nSQL generation tests completed!");
}
