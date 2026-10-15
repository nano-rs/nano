// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3462 / NAN-3468: a scheduled rule runs end to end on the OPEN schema.
//!
//! On a fresh open-core install no scheduled detection run ever completed:
//! every run died on an `ON CONFLICT (tenant_id, …)` target the open schema
//! does not have (its unique keys carry no `tenant_id`), so there were no
//! matches, alerts or signal events, and `last_run_at` never advanced. Every
//! existing detection integration test runs against an enterprise-migrated
//! database, where those targets are valid, so none of them could see it.
//!
//! This test builds the database the open edition really gets (the open
//! fresh-init path, no enterprise overlay), saves a scheduled rule WITHOUT a
//! cron (NAN-3468: it must default to every minute), and drives it through
//! the real `DistributedDetectionScheduler` (claim → execute → release):
//!
//! * staging  — the scheduler never claims it;
//! * live     — the run completes: a match row, daily stats, a signal finding
//!   in the lake finding outbox, `last_run_at` set, and no alert;
//! * alerting — the next run raises an alert and an `alert` signal finding;
//! * delete   — archives (NAN-3816): matches, stats and alerts keep the rule
//!   reference, the rule leaves the default list, a second delete is
//!   NotFound, and even a forced-due archived row is never claimed.
//!
//! Open edition only (`tenant_key!()` expands to the open key). Requires
//! Postgres at `TEST_DATABASE_URL` plus the NAN-2215 destructive opt-in, and a
//! ClickHouse with the nanosiem schema (run the open `clickhouse_migrator`
//! once) at `CLICKHOUSE_TEST_URL` (default `http://localhost:8123`, user and
//! password from `CLICKHOUSE_TEST_USER` / `CLICKHOUSE_TEST_PASSWORD`, default
//! `nanosiem` / `nanosiem`; that user needs access management, because the
//! test creates the SELECT-only raw-SQL users DualPool requires). The test drops and recreates its own Postgres
//! database, `nanosiem_open_detection_e2e`, and tags its ClickHouse rows with
//! a unique source_type.
//!
//!   Run: cargo test -p nanosiem-core --test open_detection_lifecycle_integration \
//!          -- --ignored --nocapture
#![cfg(not(feature = "enterprise"))]

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use nanosiem_core::detection::{
    DetectionError, DetectionService, DistributedDetectionScheduler, DistributedSchedulerConfig,
    MaterializedViewGenerator,
};
use nanosiem_core::lookup::{LookupService, PostgresLookupRepository};
use nanosiem_core::models::{NewDetectionRule, RuleMode};
use nanosiem_core::prevalence::PrevalenceService;
use nanosiem_core::shutdown::ShutdownToken;
use nanosiem_core::{DualPool, DualPoolConfig};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

mod common;

const TEST_DB: &str = "nanosiem_open_detection_e2e";
const RAWSQL_TEST_PASSWORD: &str = "nan3462-rawsql-test";

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn url_for(db: &str) -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], db)
}

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_TEST_USER").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_password() -> String {
    std::env::var("CLICKHOUSE_TEST_PASSWORD").unwrap_or_else(|_| "nanosiem".into())
}

async fn ch(http: &reqwest::Client, sql: &str) -> String {
    let resp = http
        .post(format!("{}/?async_insert=0&wait_end_of_query=1", ch_url()))
        .basic_auth(ch_user(), Some(ch_password()))
        .body(sql.to_string())
        .send()
        .await
        .expect("ClickHouse request");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "ClickHouse {status}: {body}\n{sql}");
    body
}

/// One probe event in the UDM `logs` table at `at`.
async fn insert_event(
    http: &reqwest::Client,
    source_type: &str,
    src_ip: &str,
    at: chrono::DateTime<Utc>,
) {
    let row = json!({
        "timestamp": at.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        "message": format!("nan3462 open lifecycle probe {}", Uuid::new_v4()),
        "source_type": source_type,
        "src_ip": src_ip,
    });
    ch(
        http,
        &format!("INSERT INTO nanosiem.logs (timestamp, message, source_type, src_ip) FORMAT JSONEachRow {row}"),
    )
    .await;
}

/// Signal findings the rule published. Since NAN-3491 (#5970) an unset log
/// query backend is the lake, so `FindingLogger` writes findings to the
/// Postgres `detection_finding_lake_outbox` (the lean drain publishes them),
/// not `source_type='findings'` rows in ClickHouse `nanosiem.logs`.
/// `signal_type` is `detection_match` or `alert` (OCSF `finding_info.types`).
async fn signal_findings(
    pool: &PgPool,
    lake_tenant: Uuid,
    rule_id: Uuid,
    signal_type: &str,
) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM detection_finding_lake_outbox \
         WHERE tenant_id = $1 AND security_tenant_id = $2 \
           AND compact_finding->>'rule_id' = $3 \
           AND ocsf_event->'finding_info'->'types' ? $4",
    )
    .bind(lake_tenant.to_string())
    .bind(lake_tenant)
    .bind(rule_id.to_string())
    .bind(signal_type)
    .fetch_one(pool)
    .await
    .expect("count lake finding outbox rows")
}

async fn count(pool: &PgPool, sql: &str, rule_id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

async fn last_run_at(pool: &PgPool, rule_id: Uuid) -> Option<chrono::DateTime<Utc>> {
    sqlx::query_scalar("SELECT last_run_at FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("last_run_at")
}

/// Make the rule due now, then wait for the scheduler to release it with a
/// `last_run_at` later than `after`.
async fn run_once(
    pool: &PgPool,
    rule_id: Uuid,
    after: Option<chrono::DateTime<Utc>>,
) -> chrono::DateTime<Utc> {
    sqlx::query(
        "UPDATE detection_rules SET next_run_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(rule_id)
    .execute(pool)
    .await
    .expect("make rule due");
    for _ in 0..120 {
        if let Some(at) = last_run_at(pool, rule_id).await {
            if after.is_none_or(|prev| at > prev) {
                return at;
            }
        }
        tokio::time::sleep(StdDuration::from_millis(500)).await;
    }
    panic!("the scheduler never completed a run of rule {rule_id} within 60 s (NAN-3462)");
}

#[test]
#[ignore = "needs Postgres + ClickHouse; run with --ignored"]
fn scheduled_rule_runs_staging_live_alerting_on_the_open_schema() {
    // The detection futures are deep in a debug build and overflow the default
    // 2 MiB test-thread stack; run on a thread with room to spare.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(64 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(lifecycle())
        })
        .expect("spawn test thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn lifecycle() {
    // Surface scheduler/execution errors in the test output (RUST_LOG to tune).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    common::assert_destructive_opt_in(&admin_url());
    let http = reqwest::Client::new();
    let tables = ch(&http, "EXISTS TABLE nanosiem.logs FORMAT TSV").await;
    assert_eq!(
        tables.trim(),
        "1",
        "ClickHouse at {} has no nanosiem.logs; run the open clickhouse_migrator first",
        ch_url()
    );

    // ---- the open fresh-init Postgres schema --------------------------------
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connect admin db");
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{TEST_DB}' AND pid <> pg_backend_pid()"
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {TEST_DB}").as_str())
        .await
        .expect("drop test db");
    admin
        .execute(format!("CREATE DATABASE {TEST_DB}").as_str())
        .await
        .expect("create test db");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
    // NAN-3491: findings publish to the lake outbox under the install's lake
    // tenant; without one every finding write fails.
    let lake_tenant = Uuid::new_v4();
    std::env::set_var("NANO_LAKE_TENANT_ID", lake_tenant.to_string());
    let mut config = DualPoolConfig::with_auth(
        url_for(TEST_DB),
        ch_url(),
        "nanosiem",
        ch_user(),
        ch_password(),
    );
    // The raw-SQL feature identities (NAN-2001) are separate, SELECT-only
    // ClickHouse users, and DualPool refuses to boot without them. Create them
    // on the throwaway ClickHouse (idempotent).
    for user in ["nanosiem_rawsql", "nanosiem_rawsql_noaudit"] {
        ch(
            &http,
            &format!("CREATE USER IF NOT EXISTS {user} IDENTIFIED BY '{RAWSQL_TEST_PASSWORD}'"),
        )
        .await;
        // DualPool requires a SELECT on `logs` and nothing broader than its
        // allowlist; `logs` alone satisfies both.
        ch(&http, &format!("REVOKE ALL ON *.* FROM {user}")).await;
        ch(&http, &format!("GRANT SELECT ON nanosiem.logs TO {user}")).await;
    }
    config.clickhouse_rawsql_password = Some(RAWSQL_TEST_PASSWORD.to_string());
    config.clickhouse_rawsql_noaudit_password = Some(RAWSQL_TEST_PASSWORD.to_string());
    {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url_for(TEST_DB))
            .await
            .expect("connect test db");
        nanosiem_core::db::run_postgres_migrations(&pool)
            .await
            .expect("open fresh-init migrations");
        let tenant_column: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_name = 'detection_matches' AND column_name = 'tenant_id')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !tenant_column,
            "expected the OPEN schema (no tenant_id on detection_matches)"
        );
        pool.close().await;
    }

    let dual_pool = DualPool::new(&config).await.expect("DualPool");
    let pg = dual_pool.postgres().clone();
    let lookup = LookupService::new(PostgresLookupRepository::new(pg.clone()));
    let prevalence =
        PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());
    let svc = DetectionService::with_dual_pool_and_prevalence(&dual_pool, lookup, prevalence);

    // ---- a scheduled rule saved without a cron (NAN-3468) -------------------
    let source_type = format!("nan3462open{:x}", Utc::now().timestamp_micros());
    let rule: NewDetectionRule = serde_json::from_value(json!({
        "name": format!("nan3462 open lifecycle {source_type}"),
        "description": "NAN-3462 open-schema lifecycle probe",
        "query": format!("source_type={source_type}"),
        "severity": "high",
        "mode": "staging",
        "lookback_minutes": 15,
    }))
    .expect("NewDetectionRule");
    let rule = svc.create_rule(rule).await.expect("create_rule");
    assert_eq!(
        rule.schedule_cron.as_deref(),
        Some("* * * * *"),
        "a scheduled rule saved without a cron must default to every minute (NAN-3468)"
    );

    insert_event(
        &http,
        &source_type,
        "10.34.62.1",
        Utc::now() - Duration::minutes(2),
    )
    .await;

    let shutdown = ShutdownToken::new();
    let scheduler_config = DistributedSchedulerConfig {
        poll_interval_secs: 1,
        phase_max_secs: 0,
        ..DistributedSchedulerConfig::default()
    };
    let scheduler = Arc::new(DistributedDetectionScheduler::new(
        svc.clone(),
        pg.clone(),
        scheduler_config,
        format!("nan3462-test-{}", Uuid::new_v4()),
    ));
    let handle = scheduler.start_with_shutdown(shutdown.clone());

    // ---- staging: never claimed ---------------------------------------------
    sqlx::query(
        "UPDATE detection_rules SET next_run_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(rule.id)
    .execute(&pg)
    .await
    .unwrap();
    tokio::time::sleep(StdDuration::from_secs(4)).await;
    assert_eq!(
        last_run_at(&pg, rule.id).await,
        None,
        "a staging rule must not run"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM detection_matches WHERE rule_id = $1",
            rule.id
        )
        .await,
        0
    );

    // ---- live: the run completes, matches counted, no alert -----------------
    svc.set_mode(rule.id, "live")
        .await
        .expect("promote to live");
    let live_run = run_once(&pg, rule.id, None).await;
    assert!(
        count(
            &pg,
            "SELECT count(*) FROM detection_matches WHERE rule_id = $1",
            rule.id
        )
        .await
            >= 1,
        "live run recorded no detection_matches"
    );
    assert!(
        count(
            &pg,
            "SELECT count(*) FROM detection_daily_stats WHERE rule_id = $1",
            rule.id
        )
        .await
            >= 1,
        "live run recorded no detection_daily_stats"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM alerts WHERE rule_id = $1",
            rule.id
        )
        .await,
        0,
        "live mode must not alert"
    );
    assert!(
        signal_findings(&pg, lake_tenant, rule.id, "detection_match").await >= 1,
        "live run published no detection_match finding to the lake outbox"
    );

    // ---- alerting: the next run raises an alert -----------------------------
    svc.set_mode(rule.id, "alerting")
        .await
        .expect("promote to alerting");
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    insert_event(&http, &source_type, "10.34.62.2", Utc::now()).await;
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    run_once(&pg, rule.id, Some(live_run)).await;
    let alerts = count(
        &pg,
        "SELECT count(*) FROM alerts WHERE rule_id = $1",
        rule.id,
    )
    .await;
    let alert_signals = signal_findings(&pg, lake_tenant, rule.id, "alert").await;

    // ---- delete archives: history survives, the rule never runs (NAN-3816) --
    let matches_before = count(
        &pg,
        "SELECT count(*) FROM detection_matches WHERE rule_id = $1",
        rule.id,
    )
    .await;
    let stats_before = count(
        &pg,
        "SELECT count(*) FROM detection_daily_stats WHERE rule_id = $1",
        rule.id,
    )
    .await;
    let mv_gen = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());
    let mut deleted = false;
    for _ in 0..40 {
        match svc.delete_rule_with_mode(rule.id, &mv_gen).await {
            Ok(()) => {
                deleted = true;
                break;
            }
            // A run still holds the claim: the API answers 409, callers retry.
            Err(DetectionError::RuleExecuting(_)) => {
                tokio::time::sleep(StdDuration::from_millis(500)).await
            }
            Err(error) => panic!("delete_rule_with_mode: {error}"),
        }
    }
    assert!(deleted, "delete never drained the rule's claim");
    let archived = svc.get_rule(rule.id).await.expect("deleted rule row kept");
    assert!(archived.archived, "DELETE must archive the rule");
    assert_eq!(archived.mode, RuleMode::Staging);
    assert_eq!(archived.next_run_at, None);
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM detection_matches WHERE rule_id = $1",
            rule.id
        )
        .await,
        matches_before,
        "deleting a rule erased its detection_matches"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM detection_daily_stats WHERE rule_id = $1",
            rule.id
        )
        .await,
        stats_before,
        "deleting a rule erased its daily stats"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM alerts WHERE rule_id = $1",
            rule.id
        )
        .await,
        alerts,
        "deleting a rule unlinked its alerts"
    );
    assert!(
        !svc.list_rules()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == rule.id),
        "an archived rule must be hidden from the default list"
    );
    assert!(
        svc.list_all_rules()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == rule.id),
        "include_archived must still list it"
    );
    // Deleting again changes nothing and reports NotFound (hosted parity).
    assert!(matches!(
        svc.delete_rule_with_mode(rule.id, &mv_gen).await,
        Err(DetectionError::RuleNotFound(_))
    ));
    assert!(svc.get_rule(rule.id).await.unwrap().archived);
    // Even forced back to alerting and due, an archived rule is never claimed.
    let archived_run = last_run_at(&pg, rule.id).await;
    sqlx::query(
        "UPDATE detection_rules SET mode = 'alerting', \
         next_run_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(rule.id)
    .execute(&pg)
    .await
    .unwrap();
    tokio::time::sleep(StdDuration::from_secs(4)).await;
    assert_eq!(
        last_run_at(&pg, rule.id).await,
        archived_run,
        "an archived (deleted) rule must never run"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM detection_matches WHERE rule_id = $1",
            rule.id
        )
        .await,
        matches_before
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(StdDuration::from_secs(10), handle).await;
    let _ = svc.delete_rule(rule.id).await;
    // Best effort: the probe rows carry a unique source_type, so leftovers are inert.
    let _ = http
        .post(ch_url())
        .basic_auth(ch_user(), Some(ch_password()))
        .body(format!(
            "DELETE FROM nanosiem.logs WHERE source_type = '{source_type}'"
        ))
        .send()
        .await;

    assert!(alerts >= 1, "alerting run raised no alert");
    assert!(
        alert_signals >= 1,
        "alerting run published no alert finding to the lake outbox"
    );
}
