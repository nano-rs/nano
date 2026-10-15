//! Shared API/jobs session exceptions with the normal application pool on 6432.
use nanosiem_core::{db::{connection_budget, pooler}, leader::LeaderElection, shutdown::ShutdownToken};
use sqlx::PgPool;
use std::time::Duration;

fn pool() -> PgPool {
    pooler::connect_lazy(connection_budget::pool_options(4),
        &std::env::var("PGBOUNCER_TEST_DATABASE_URL").unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires local PgBouncer and NANOSIEM_SESSION_DATABASE_URL"]
async fn transaction_pool_api_cross_commit_rule_fence() {
    let pool = pool();
    let direct = pooler::session_pool(&pool).unwrap();
    assert_eq!(direct.options().get_max_connections(), 2);
    assert_eq!(direct.options().get_min_connections(), 0);
    assert!(direct.options().get_idle_timeout().unwrap() <= Duration::from_secs(30));
    assert!(direct.options().get_max_lifetime().unwrap() <= Duration::from_secs(1800));
    let rule = uuid::Uuid::new_v4();
    let guard = nanosiem_core::detection::materialized_view::acquire_rule_runtime_lock(&pool, rule).await.unwrap();
    // Ordinary application work commits through PgBouncer while the direct
    // fence still excludes a competing transaction on any server backend.
    for _ in 0..4 {
        let mut tx = pool.begin().await.unwrap();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1::text, 5638868622159100997))")
            .bind(rule.to_string()).fetch_one(&mut *tx).await.unwrap();
        assert!(!acquired);
        tx.commit().await.unwrap();
    }
    drop(guard);
    let guard = tokio::time::timeout(Duration::from_secs(5),
        nanosiem_core::detection::materialized_view::acquire_rule_runtime_lock(&pool, rule)).await.unwrap().unwrap();
    drop(guard);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires local PgBouncer and NANOSIEM_SESSION_DATABASE_URL"]
async fn transaction_pool_jobs_leader_releases_on_shutdown() {
    let pool = pool();
    let shutdown = ShutdownToken::new();
    let lock = 2446001;
    let election = LeaderElection::new(pool.clone(), lock);
    let (mut leader, handle) = election.start(shutdown.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !*leader.borrow() { leader.changed().await.unwrap(); }
    }).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock).fetch_one(&mut *tx).await.unwrap();
    assert!(!acquired);
    tx.rollback().await.unwrap();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
    assert!(!*leader.borrow());
    let mut tx = pool.begin().await.unwrap();
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock).fetch_one(&mut *tx).await.unwrap();
    assert!(acquired);
    tx.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_SESSION_DATABASE_URL pointing at local Postgres"]
async fn transaction_pool_jobs_direct_bridge_preserves_app_checkout() {
    // During image-first rollout DATABASE_URL is still direct. Leadership must
    // not exhaust a max-1 application pool while holding its lifetime lock.
    let url = std::env::var("NANOSIEM_SESSION_DATABASE_URL").unwrap();
    let pool = pooler::connect_lazy(connection_budget::pool_options(1), &url).unwrap();
    let shutdown = ShutdownToken::new();
    let election = LeaderElection::new(pool.clone(), 2446002);
    let (mut leader, handle) = election.start(shutdown.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !*leader.borrow() { leader.changed().await.unwrap(); }
    }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), sqlx::query("SELECT 1").execute(&pool))
        .await.unwrap().unwrap();
    assert!(*leader.borrow());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
    pool.close().await;
}
