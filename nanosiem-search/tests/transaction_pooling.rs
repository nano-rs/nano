//! The search service's actual lake-mode pool constructor through PgBouncer.
use nanosiem_core::{DualPool, DualPoolConfig};
use sqlx::Connection;

#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(type_name = "pooling_test_mood", rename_all = "lowercase")]
enum PoolingTestMood { Ready, Done }


#[tokio::test]
#[ignore = "requires local transaction PgBouncer"]
async fn transaction_pool_search_typed_queries_under_contention() {
    let mut config = DualPoolConfig::default();
    config.postgres_url = std::env::var("PGBOUNCER_TEST_DATABASE_URL").unwrap();
    let dual = DualPool::new_lake_control_plane(&config).await.unwrap();
    let pool = dual.postgres();
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..12_i64 {
        let pool = pool.clone();
        tasks.spawn(async move {
            for _ in 0..8 {
                let echoed: i64 = sqlx::query_scalar("SELECT $1::bigint")
                    .bind(n).fetch_one(&pool).await.unwrap();
                assert_eq!(echoed, n);
                let mut tx = pool.begin().await.unwrap();
                let timeout: String = sqlx::query_scalar("SHOW statement_timeout")
                    .fetch_one(&mut *tx).await.unwrap();
                assert_eq!(timeout, "0", "SET LOCAL must not leak to the next transaction");
                sqlx::query("SET LOCAL statement_timeout = '5s'").execute(&mut *tx).await.unwrap();
                let value: (i64, Vec<String>, serde_json::Value) = sqlx::query_as("SELECT $1::bigint, $2::text[], $3::jsonb")
                    .bind(n).bind(vec!["search".to_owned()]).bind(serde_json::json!({"query":n}))
                    .fetch_one(&mut *tx).await.unwrap();
                assert_eq!(value.0, n);
                assert_eq!(value.1, ["search"]);
                assert_eq!(value.2["query"], n);
                let mood: PoolingTestMood = sqlx::query_scalar("SELECT 'ready'::pooling_test_mood")
                    .fetch_one(&mut *tx).await.unwrap();
                assert_eq!(mood, PoolingTestMood::Ready);
                let named: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_prepared_statements WHERE name LIKE 'sqlx_%'")
                    .fetch_one(&mut *tx).await.unwrap();
                assert_eq!(named, 0, "zero cache capacity must also mean no named protocol statements");
                assert_eq!((&mut *tx).cached_statements_size(), 0);
                tx.commit().await.unwrap();
            }
        });
    }
    while let Some(result) = tasks.join_next().await { result.unwrap(); }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires local PgBouncer and NANOSIEM_SESSION_DATABASE_URL"]
async fn transaction_pool_uncached_describe_and_direct_cache() {
    use nanosiem_core::db::{connection_budget, pooler};
    use sqlx::Executor;
    let url = std::env::var("PGBOUNCER_TEST_DATABASE_URL").unwrap();
    let pool = pooler::connect_lazy(connection_budget::pool_options(1), &url).unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let description = (&mut *connection).describe("SELECT 1::bigint AS value").await.unwrap();
    assert_eq!(description.columns().len(), 1);
    assert_eq!(description.nullable(0), None);
    assert_eq!(connection.cached_statements_size(), 0);
    drop(connection);
    pool.close().await;

    // Positive-capacity connections retain normal named-statement caching.
    let direct = std::env::var("NANOSIEM_SESSION_DATABASE_URL").unwrap();
    let options = pooler::options(&direct).unwrap().statement_cache_capacity(2);
    let pool = connection_budget::pool_options(1).connect_lazy_with(options);
    let mut connection = pool.acquire().await.unwrap();
    for value in 0..4_i64 {
        let echoed: i64 = sqlx::query_scalar("SELECT $1::bigint")
            .bind(value).fetch_one(&mut *connection).await.unwrap();
        assert_eq!(echoed, value);
    }
    assert_eq!(connection.cached_statements_size(), 1);
    drop(connection);
    pool.close().await;
}
