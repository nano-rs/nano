// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5303 / NAN-5315 against real databases.
//!
//! - **NAN-5303**: a real-time rule writes `detection_matches`. Drives the real
//!   pipeline: rule → MV (live CH) → INSERT logs → MV writes `signals` →
//!   `SignalProcessor` → `detection_matches` in Postgres. Asserts a Grouped
//!   rule gets ONE review row per poll cycle carrying every event (not one row
//!   per signal), a PerEvent rule one row per event, and a Staging rule none.
//! - **NAN-5315**: `DetectionService::create_rule` writes v1
//!   (`initial_creation`) to `detection_rule_versions`.
//!
//! Each test migrates its own scratch Postgres database. Point the suite at
//! DISPOSABLE servers only (the CH side creates MVs and inserts into
//! `nanosiem.logs`):
//!
//! ```bash
//! NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 \
//! NANOSIEM_E2E_PG_URL=postgres://nanosiem:nanosiem@127.0.0.1:<port>/nanosiem \
//! NANOSIEM_E2E_CH_URL=http://127.0.0.1:<port> \
//! NANOSIEM_E2E_CH_USER=nanosiem_admin NANOSIEM_E2E_CH_PASSWORD=... \
//! CLICKHOUSE_RAWSQL_PASSWORD=... CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=... \
//! NANO_SCHEMA_PROFILE=udm \
//! cargo test -p nanosiem-core --test realtime_detection_matches_e2e -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use nanosiem_core::db::repository::DetectionRuleRepository;
use nanosiem_core::db::{run_postgres_migrations, DualPool, DualPoolConfig};
use nanosiem_core::detection::{
    DetectionService, MaterializedViewGenerator, SignalProcessor, SignalProcessorConfig,
};
use nanosiem_core::lookup::{LookupService, PostgresLookupRepository};
use nanosiem_core::models::{AlertMode, DetectionMode, NewDetectionRule, RuleMode, Severity};
use nanosiem_core::prevalence::PrevalenceService;
use sqlx::PgPool;
use uuid::Uuid;

const PHASE_TIMEOUT: Duration = Duration::from_secs(60);

struct Env {
    pg_admin_url: String,
    ch_url: String,
    ch_user: String,
    ch_password: String,
}

fn env() -> Env {
    assert_eq!(
        std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(),
        Ok("1"),
        "set NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 against DISPOSABLE PG + CH"
    );
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is required"));
    Env {
        pg_admin_url: var("NANOSIEM_E2E_PG_URL"),
        ch_url: var("NANOSIEM_E2E_CH_URL"),
        ch_user: var("NANOSIEM_E2E_CH_USER"),
        ch_password: var("NANOSIEM_E2E_CH_PASSWORD"),
    }
}

/// Fresh, migrated scratch database on the disposable server.
async fn scratch_db(env: &Env, name: &str) -> (PgPool, String, PgPool) {
    let admin = PgPool::connect(&env.pg_admin_url).await.expect("connect PG");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .expect("drop scratch");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create scratch");
    let base = env
        .pg_admin_url
        .rsplit_once('/')
        .map(|(b, _)| b)
        .expect("PG url has a database");
    let url = format!("{base}/{name}");
    let pg = PgPool::connect(&url).await.expect("connect scratch");
    run_postgres_migrations(&pg).await.expect("migrate scratch");
    (pg, url, admin)
}

async fn dual_pool(env: &Env, pg_url: &str) -> DualPool {
    let mut config = DualPoolConfig::with_auth(
        pg_url.to_string(),
        env.ch_url.clone(),
        "nanosiem",
        env.ch_user.clone(),
        env.ch_password.clone(),
    );
    // NAN-2001: the raw-SQL feature identities are required at boot.
    config.clickhouse_rawsql_password = std::env::var("CLICKHOUSE_RAWSQL_PASSWORD").ok();
    config.clickhouse_rawsql_noaudit_password =
        std::env::var("CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD").ok();
    DualPool::new(&config).await.expect("dual pool")
}

fn rule(name: &str, source: &str, mode: RuleMode, alert_mode: AlertMode) -> NewDetectionRule {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "description": "NAN-5303 e2e",
        "query": format!("source_type=\"{source}\""),
        "severity": "high",
        "mode": mode,
        "realtime_enabled": true,
        "detection_mode": DetectionMode::RealTime,
        "risk_score": 50,
        "risk_entity_field": "src_ip",
        "auto_tuning_enabled": false,
        "alert_mode": alert_mode,
    }))
    .expect("NewDetectionRule")
}

async fn insert_events(ch: &clickhouse::Client, source: &str, n: usize) {
    let base = Utc::now() - ChronoDuration::minutes(30);
    let rows: Vec<String> = (0..n)
        .map(|i| {
            let ts = (base + ChronoDuration::seconds(i as i64))
                .format("%Y-%m-%d %H:%M:%S%.6f")
                .to_string();
            format!(
                "(generateUUIDv4(), toDateTime64('{ts}', 6), '{source}', 'nan5303 evt {i}', '10.53.0.{}')",
                i % 4
            )
        })
        .collect();
    ch.clone()
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .query(&format!(
            "INSERT INTO nanosiem.logs (id, timestamp, source_type, message, src_ip) VALUES {}",
            rows.join(", ")
        ))
        .execute()
        .await
        .expect("insert logs");
}

/// (row count, summed event_count) of a rule's `detection_matches`.
async fn matches(pg: &PgPool, rule_id: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*), COALESCE(sum(event_count), 0)::bigint FROM detection_matches WHERE rule_id = $1",
    )
    .bind(rule_id)
    .fetch_one(pg)
    .await
    .expect("count detection_matches")
}

async fn wait_events(pg: &PgPool, rule_id: Uuid, at_least: i64) -> (i64, i64) {
    let start = Instant::now();
    loop {
        let got = matches(pg, rule_id).await;
        if got.1 >= at_least || start.elapsed() > PHASE_TIMEOUT {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test]
#[ignore = "needs disposable PG + CH (see module docs)"]
async fn realtime_rules_write_batched_detection_matches() {
    let env = env();
    let (pg, pg_url, admin) = scratch_db(&env, "nan5303_e2e").await;
    let dual_pool = dual_pool(&env, &pg_url).await;

    sqlx::query(
        "INSERT INTO signal_processor_watermarks (id, last_inserted_at, last_signal_id, processed_count, updated_at)
         VALUES ('default', NOW(), NULL, 0, NOW())
         ON CONFLICT (id) DO UPDATE SET last_inserted_at = NOW(), last_signal_id = NULL",
    )
    .execute(&pg)
    .await
    .expect("seed watermark");

    let tag = format!("{:x}", Utc::now().timestamp_micros());
    let (g_src, p_src, s_src) = (
        format!("nan5303g{tag}"),
        format!("nan5303p{tag}"),
        format!("nan5303s{tag}"),
    );
    let repo = DetectionRuleRepository::new(pg.clone());
    let grouped = repo
        .create(&rule("rt grouped live", &g_src, RuleMode::Live, AlertMode::Grouped))
        .await
        .expect("grouped");
    let per_event = repo
        .create(&rule("rt per-event", &p_src, RuleMode::Alerting, AlertMode::PerEvent))
        .await
        .expect("per-event");
    let staging = repo
        .create(&rule("rt staging", &s_src, RuleMode::Staging, AlertMode::Grouped))
        .await
        .expect("staging");

    let mv_gen = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());
    let mut mvs = Vec::new();
    for r in [&grouped, &per_event, &staging] {
        mvs.push(mv_gen.create_view(r).await.expect("create MV"));
    }

    // All signals are inserted BEFORE the processor starts so one poll
    // cycle (batch_size 100) drains each rule's burst together.
    let ch = dual_pool.clickhouse().clone();
    insert_events(&ch, &g_src, 40).await;
    insert_events(&ch, &p_src, 3).await;
    insert_events(&ch, &s_src, 5).await;
    // Let the signals pass the processor's 5s settling lag.
    tokio::time::sleep(Duration::from_secs(7)).await;

    let processor = SignalProcessor::new(
        dual_pool.clone(),
        SignalProcessorConfig {
            poll_interval_ms: 300,
            batch_size: 100,
            ..SignalProcessorConfig::default()
        },
    );
    let handle = processor.start().await.expect("start processor");

    let g = wait_events(&pg, grouped.id, 40).await;
    let p = wait_events(&pg, per_event.id, 3).await;
    // Give the staging signals the same chance to (wrongly) land.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let s = matches(&pg, staging.id).await;
    let live_count: i64 =
        sqlx::query_scalar("SELECT live_match_count::bigint FROM detection_rules WHERE id = $1")
            .bind(grouped.id)
            .fetch_one(&pg)
            .await
            .expect("live_match_count");

    processor.stop();
    handle.abort();
    let admin_ch = dual_pool.clickhouse_admin().clone();
    for mv in &mvs {
        let _ = admin_ch.query(&format!("DROP VIEW IF EXISTS {mv}")).execute().await;
    }
    pg.close().await;
    let _ = sqlx::query("DROP DATABASE IF EXISTS nan5303_e2e WITH (FORCE)")
        .execute(&admin)
        .await;

    assert_eq!(g, (1, 40), "Grouped Live rule: ONE batched review row with all 40 events");
    assert_eq!(live_count, 40, "Live bake-in still counts every signal");
    assert_eq!(p, (3, 3), "PerEvent rule: one review row per event");
    assert_eq!(s, (0, 0), "Staging rule writes nothing");
}

#[tokio::test]
#[ignore = "needs disposable PG + CH (see module docs)"]
async fn create_rule_records_initial_version() {
    let env = env();
    let (pg, pg_url, admin) = scratch_db(&env, "nan5315_e2e").await;
    let dual_pool = dual_pool(&env, &pg_url).await;
    let lookup = LookupService::new(PostgresLookupRepository::new(pg.clone()));
    let prevalence =
        PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());
    let svc = DetectionService::with_dual_pool_and_prevalence(&dual_pool, lookup, prevalence);

    let mut new_rule = rule("nan5315 v1", "nan5315", RuleMode::Staging, AlertMode::Grouped);
    new_rule.detection_mode = Some(DetectionMode::Scheduled);
    new_rule.realtime_enabled = Some(false);
    new_rule.schedule_cron = Some("*/5 * * * *".into());
    new_rule.severity = Severity::Medium;
    let created = svc.create_rule(new_rule).await.expect("create_rule");

    let versions: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT version_number, change_reason, query FROM detection_rule_versions WHERE rule_id = $1 ORDER BY version_number",
    )
    .bind(created.id)
    .fetch_all(&pg)
    .await
    .expect("versions");

    pg.close().await;
    let _ = sqlx::query("DROP DATABASE IF EXISTS nan5315_e2e WITH (FORCE)")
        .execute(&admin)
        .await;

    assert_eq!(
        versions,
        vec![(1, "initial_creation".to_string(), created.query.clone())],
        "create writes exactly v1 with the created query"
    );
}
