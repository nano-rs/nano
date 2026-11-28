// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5957: on a small install (PostgreSQL limited to 512 MiB) the services'
//! pools are 3 (api), 4 (jobs) and 3 (search) wide. v2.0.36 kept every
//! long-lived `LISTEN` session (case_changes, license_status_changed,
//! agentlane_config) INSIDE those pools, so nano-api had 1 connection left
//! and nano-jobs 2: constant "pool timed out", no SIEM Health report, rules
//! marked "[crash?]". The sizing (NAN-5822) budgets those sessions outside
//! the pools; `db::listener::dedicated_listener` now opens them there.
//!
//! These suites use a pool sized like the small install's nano-api pool.
//! `#[ignore]`d like the sibling DB suites: the `pg-integration-tests` lane
//! runs them with `-- --ignored`.

mod common;

use std::time::Duration;

use nanosiem_core::db::listener::{dedicated_listener, ping};
use nanosiem_core::db::repository::DetectionRuleRepository;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::PgPool;
use uuid::Uuid;

/// The small install's nano-api pool: 3 wide, and a short acquire timeout so
/// a starved pool fails the test quickly instead of after 30 s.
const SMALL_POOL: u32 = 3;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

async fn small_pool() -> PgPool {
    pool_of(SMALL_POOL).await
}

async fn pool_of(size: u32) -> PgPool {
    // Migrated through the shared helper, then a separate pool of the size
    // under test with the same connect options.
    let migrated = common::migrated_pool().await;
    PgPoolOptions::new()
        .max_connections(size)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with((*migrated.connect_options()).clone())
        .await
        .expect("connect the small pool")
}

/// Hold `n` pool connections at once, as concurrent background tasks do.
async fn hold_concurrently(pool: &PgPool, n: u32) -> Result<(), sqlx::Error> {
    let mut held = Vec::new();
    for _ in 0..n {
        held.push(pool.acquire().await?);
    }
    for conn in &mut held {
        sqlx::query("SELECT 1").execute(&mut **conn).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn dedicated_listeners_leave_the_whole_small_pool_for_queries() {
    let pool = small_pool().await;
    let channel = format!("nan5957_{}", Uuid::now_v7().simple());
    // nano-api on a small install runs two listeners (case_changes and
    // agentlane_config); open two, plus one more for margin.
    let opened_before = pool.size();
    let mut listeners = Vec::new();
    for _ in 0..3 {
        let mut listener = dedicated_listener(&pool).await.expect("dedicated listener");
        listener.listen(&channel).await.expect("LISTEN");
        listeners.push(listener);
    }
    assert_eq!(pool.size(), opened_before, "no listener opened a connection in the service pool");
    assert_eq!(pool.num_idle() as u32, pool.size(), "no listener holds a service-pool connection");

    // Every connection of the pool is still available, all at once.
    hold_concurrently(&pool, SMALL_POOL).await.expect("the whole pool is free for queries");

    // And the listeners still receive notifications.
    sqlx::query("SELECT pg_notify($1, 'ping')").bind(&channel).execute(&pool).await.unwrap();
    for listener in &mut listeners {
        let n = tokio::time::timeout(Duration::from_secs(5), listener.recv()).await.unwrap().unwrap();
        assert_eq!(n.payload(), "ping");
    }
}

/// The v2.0.36 behaviour, kept as a control: a `PgListener` built on the
/// service pool keeps one of its connections for its whole life, so two of
/// them leave a 3-wide pool with one, and work that needs two at once (the
/// Agent Lane settings page did) waits out the acquire timeout.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn pooled_listeners_starve_a_small_pool() {
    let pool = small_pool().await;
    let mut pooled = Vec::new();
    for _ in 0..2 {
        let mut listener = PgListener::connect_with(&pool).await.expect("pooled listener");
        listener.listen("nan5957_control").await.expect("LISTEN");
        pooled.push(listener);
    }
    let error = hold_concurrently(&pool, 2).await.expect_err("only one connection is left");
    assert!(matches!(error, sqlx::Error::PoolTimedOut), "got {error:?}");
}

async fn insert_claimed_rule(pool: &PgPool, node: &str) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules
            (id, name, description, query, severity, mode,
             detection_mode, schedule_cron, next_run_at, claimed_by, claimed_at, inflight_claims)
        VALUES ($1, $2, 'NAN-5957 abandon test', 'source_type=apache', 'medium',
                'alerting', 'scheduled', '* * * * *', NOW() - INTERVAL '1 minute', $3, NOW(), 1)
        "#,
    )
    .bind(rule_id)
    .bind(format!("nan5957_abandon_{rule_id}"))
    .bind(node)
    .execute(pool)
    .await
    .expect("insert claimed rule");
    rule_id
}

/// Claim the rule again the way `claim_due_rules` does (for this row only: a
/// real claim would take other suites' due rules in the shared database).
async fn reclaim(pool: &PgPool, id: Uuid, node: &str) {
    sqlx::query(
        "UPDATE detection_rules SET claimed_by = $2, claimed_at = NOW(), \
         inflight_claims = LEAST(inflight_claims, 1000) + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(node)
    .execute(pool)
    .await
    .unwrap();
}

/// NAN-5957: a claim whose run never started (its bookkeeping read timed
/// out on the pool) is given back, so the next claim does not read it as a
/// process crash and send the rule into "[crash?]" isolation.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn an_abandoned_unstarted_claim_is_not_read_as_a_crash() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());

    let given_back = insert_claimed_rule(&pool, "node-a").await;
    assert!(repo.abandon_unstarted_claim(given_back, "node-a").await.unwrap());
    reclaim(&pool, given_back, "node-a").await;
    let counters = repo.get_claimed_failure_counters(given_back, "node-a").await.unwrap().unwrap();
    assert_eq!(counters.crashed_attempts, 0, "an unstarted claim is not a crash");
    assert!(!counters.crash_suspected());

    // Control: the same claim left to expire is (by design) read as a crash.
    let expired = insert_claimed_rule(&pool, "node-a").await;
    reclaim(&pool, expired, "node-a").await;
    let counters = repo.get_claimed_failure_counters(expired, "node-a").await.unwrap().unwrap();
    assert_eq!(counters.crashed_attempts, 1);

    // Another node's claim is never given back.
    let other = insert_claimed_rule(&pool, "node-b").await;
    assert!(!repo.abandon_unstarted_claim(other, "node-a").await.unwrap());

    for id in [given_back, expired, other] {
        sqlx::query("DELETE FROM detection_rules WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    }
}

/// NAN-5957 review P2-1: giving back a reclaim over a CRASHED isolated run
/// (inflight 2, isolated_claim set by the run that died) keeps that crash's
/// attribution; giving back a claim whose own isolated mark was set clears it.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn abandoning_a_reclaim_keeps_a_crashed_isolated_runs_attribution() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());

    let crashed = insert_claimed_rule(&pool, "node-a").await;
    // The isolated run on node-a died; node-b reclaims (inflight 1 -> 2).
    sqlx::query("UPDATE detection_rules SET isolated_claim = true WHERE id = $1").bind(crashed).execute(&pool).await.unwrap();
    reclaim(&pool, crashed, "node-b").await;
    assert!(repo.abandon_unstarted_claim(crashed, "node-b").await.unwrap());
    reclaim(&pool, crashed, "node-c").await;
    let counters = repo.get_claimed_failure_counters(crashed, "node-c").await.unwrap().unwrap();
    assert_eq!(counters.crashed_attempts, 1, "the crash is still counted");
    assert!(counters.isolated_claim, "and still attributed to the isolated run");

    // Own mark, never ran: cleared.
    let own = insert_claimed_rule(&pool, "node-a").await;
    sqlx::query("UPDATE detection_rules SET isolated_claim = true WHERE id = $1").bind(own).execute(&pool).await.unwrap();
    assert!(repo.abandon_unstarted_claim(own, "node-a").await.unwrap());
    reclaim(&pool, own, "node-a").await;
    let counters = repo.get_claimed_failure_counters(own, "node-a").await.unwrap().unwrap();
    assert_eq!(counters.crashed_attempts, 0);
    assert!(!counters.isolated_claim);

    for id in [crashed, own] {
        sqlx::query("DELETE FROM detection_rules WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    }
}

/// NAN-5957 review P2-2: an ingestion pause transition holds the transition
/// lock on ONE connection and runs every statement on it, so it works on a
/// 1-wide pool (the underfunded nano-api tier). Before, it took a second
/// connection while holding the first and timed out. ClickHouse is
/// unreachable here on purpose: guard failures are logged, not fatal.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn an_ingestion_pause_transition_needs_only_one_connection() {
    use nanosiem_core::settings::{IngestionPauseService, IngestionPauseSource};
    let pool = pool_of(1).await;
    let ch = clickhouse::Client::default().with_url("http://127.0.0.1:1");
    let service = IngestionPauseService::new(pool.clone(), ch);
    let before = service.state().await.unwrap();
    assert!(!before.paused, "the shared test database must start unpaused");

    let (state, changed) = service
        .pause(IngestionPauseSource::Manual, Some("nan5957 small-pool test"), None)
        .await
        .expect("pause on a 1-wide pool");
    assert!(changed && state.paused);
    let (_, changed) = service.resume(false).await.expect("resume on a 1-wide pool");
    assert!(changed);
    assert!(!service.state().await.unwrap().paused);
    // The pool's one connection went back (unlocked), not closed: the next
    // transition still works.
    service.reconcile().await.ok();
    assert!(!service.state().await.unwrap().paused);
}

/// NAN-5957 review P2-3: the keepalive pings the listener's own session; a
/// dead session fails the ping (the caller reconnects) and never touches the
/// service pool.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_listener_keepalive_ping_detects_a_dead_session() {
    let pool = small_pool().await;
    let channel = format!("nan5957_ping_{}", Uuid::now_v7().simple());
    let mut listener = dedicated_listener(&pool).await.unwrap();
    listener.listen(&channel).await.unwrap();
    ping(&mut listener).await.expect("live session answers");

    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut listener).await.unwrap();
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&pool).await.unwrap();
    assert!(killed, "terminated the listener's session");
    // The terminated session cannot answer.
    let mut failed = false;
    for _ in 0..20 {
        if ping(&mut listener).await.is_err() {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(failed, "a dead session fails the keepalive ping");
    hold_concurrently(&pool, SMALL_POOL).await.expect("the service pool is untouched");
}
