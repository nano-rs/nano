// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5428 against real databases: one failing real-time signal must not
//! stall the other real-time rules, and a dropped signal must be recorded.
//!
//! Drives the real pipeline (rule → MV → INSERT logs → `signals` →
//! `SignalProcessor` → alerts) with three Alerting real-time rules whose
//! signals are queued in this order:
//!
//! 1. **poison**: its alert write fails deterministically (a scratch-database
//!    trigger raises SQLSTATE 22023 for its events);
//! 2. **nul**: its matched event carries U+0000, which PostgreSQL rejects in
//!    jsonb (22P05) unless the processor sanitizes it;
//! 3. **control**: ordinary events behind both.
//!
//! Before the fix the poison signal held the shared watermark for ~5 minutes
//! (backoff until 10 consecutive errors), then was skipped with a log line.
//! Now the control rule alerts within seconds, the NUL event alerts with
//! U+FFFD in place of U+0000, and the poison signal is a coverage gap plus a
//! minimal reference alert (identifiers only).
//!
//! A second test drives the systemic breaker: a fault that fails every
//! signal with the same unrecognised error dead-letters only the first few
//! signals, then holds the lane and marks the rule failing (health critical).
//!
//! Point the suite at DISPOSABLE servers only:
//!
//! ```bash
//! NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 \
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:nanosiem@127.0.0.1:<port>/nanosiem \
//! CLICKHOUSE_TEST_URL=http://127.0.0.1:<port> \
//! CLICKHOUSE_TEST_USER=nanosiem_admin CLICKHOUSE_TEST_PASSWORD=... \
//! CLICKHOUSE_RAWSQL_PASSWORD=... CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=... \
//! NANO_SCHEMA_PROFILE=udm \
//! cargo test -p nanosiem-core --test realtime_signal_isolation_e2e -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use nanosiem_core::db::repository::DetectionRuleRepository;
use nanosiem_core::db::{run_postgres_migrations, DualPool, DualPoolConfig};
use nanosiem_core::detection::{MaterializedViewGenerator, SignalProcessor, SignalProcessorConfig};
use nanosiem_core::models::{AlertMode, DetectionMode, NewDetectionRule, RuleMode};
use sqlx::PgPool;
use uuid::Uuid;

/// The control rule must alert well inside the old ~5 minute stall.
const CONTROL_DEADLINE: Duration = Duration::from_secs(30);
const POISON_MARKER: &str = "nan5428-poison";
const SCRATCH_DB: &str = "nan5428_e2e";

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
    Env {
        pg_admin_url: nanosiem_test_db::require_pg_url(),
        ch_url: nanosiem_test_db::require_ch_url(),
        ch_user: nanosiem_test_db::ch_user().unwrap_or_else(|| panic!("CLICKHOUSE_TEST_USER is required")),
        ch_password: nanosiem_test_db::ch_password().unwrap_or_default(),
    }
}

async fn scratch_db(env: &Env) -> (PgPool, String, PgPool) {
    let admin = PgPool::connect(&env.pg_admin_url).await.expect("connect PG");
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)")))
        .execute(&admin)
        .await
        .expect("drop scratch");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {SCRATCH_DB}")))
        .execute(&admin)
        .await
        .expect("create scratch");
    let base = env
        .pg_admin_url
        .rsplit_once('/')
        .map(|(b, _)| b)
        .expect("PG url has a database");
    let url = format!("{base}/{SCRATCH_DB}");
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
    config.clickhouse_rawsql_password = std::env::var("CLICKHOUSE_RAWSQL_PASSWORD").ok();
    config.clickhouse_rawsql_noaudit_password =
        std::env::var("CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD").ok();
    DualPool::new(&config).await.expect("dual pool")
}

fn rule(name: &str, source: &str) -> NewDetectionRule {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "description": "NAN-5428 e2e",
        "query": format!("source_type=\"{source}\""),
        "severity": "high",
        "mode": RuleMode::Alerting,
        "realtime_enabled": true,
        "detection_mode": DetectionMode::RealTime,
        "risk_score": 50,
        "risk_entity_field": "src_ip",
        "auto_tuning_enabled": false,
        "alert_mode": AlertMode::PerEvent,
    }))
    .expect("NewDetectionRule")
}

/// Insert `n` events; `message_sql` is a ClickHouse expression of `i`.
async fn insert_events(ch: &clickhouse::Client, source: &str, n: usize, message_sql: &str) {
    let base = Utc::now() - ChronoDuration::minutes(30);
    let rows: Vec<String> = (0..n)
        .map(|i| {
            let ts = (base + ChronoDuration::seconds(i as i64))
                .format("%Y-%m-%d %H:%M:%S%.6f")
                .to_string();
            let message = message_sql.replace("{i}", &i.to_string());
            format!("(generateUUIDv4(), toDateTime64('{ts}', 6), '{source}', {message}, '10.54.28.{i}')")
        })
        .collect();
    ch.clone()
        .with_setting("async_insert", "0")
        .with_setting("wait_end_of_query", "1")
        .query(&format!(
            "INSERT INTO nanosiem.logs (id, timestamp, source_type, message, src_ip) VALUES {}",
            rows.join(", ")
        ))
        .execute()
        .await
        .expect("insert logs");
}

async fn alerts(pg: &PgPool, rule_id: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar("SELECT matched_events FROM alerts WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_all(pg)
        .await
        .expect("alerts")
}

async fn gaps(pg: &PgPool, rule_id: Uuid) -> Vec<(i32, String)> {
    sqlx::query_as(
        "SELECT attempts, error_message FROM detection_coverage_gaps WHERE rule_id = $1",
    )
    .bind(rule_id)
    .fetch_all(pg)
    .await
    .expect("coverage gaps")
}

#[tokio::test]
#[ignore = "needs disposable PG + CH (see module docs)"]
async fn one_failing_signal_does_not_stall_other_realtime_rules() {
    let env = env();
    let (pg, pg_url, admin) = scratch_db(&env).await;
    let dual_pool = dual_pool(&env, &pg_url).await;

    sqlx::query(
        "INSERT INTO signal_processor_watermarks (id, last_inserted_at, last_signal_id, processed_count, updated_at)
         VALUES ('default', NOW(), NULL, 0, NOW())
         ON CONFLICT (id) DO UPDATE SET last_inserted_at = NOW(), last_signal_id = NULL",
    )
    .execute(&pg)
    .await
    .expect("seed watermark");

    // Deterministic alert-write failure for the poison rule's events only.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE FUNCTION nan5428_poison() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.matched_events::text LIKE '%{POISON_MARKER}%' THEN
                RAISE EXCEPTION 'nan5428 injected data error' USING ERRCODE = '22023';
            END IF;
            RETURN NEW;
        END $$;
        "#
    )))
    .execute(&pg)
    .await
    .expect("poison function");
    sqlx::query(
        "CREATE TRIGGER nan5428_poison BEFORE INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION nan5428_poison()",
    )
    .execute(&pg)
    .await
    .expect("poison trigger");

    let tag = format!("{:x}", Utc::now().timestamp_micros());
    let (poison_src, nul_src, control_src) = (
        format!("nan5428p{tag}"),
        format!("nan5428n{tag}"),
        format!("nan5428c{tag}"),
    );
    let repo = DetectionRuleRepository::new(pg.clone());
    let poison = repo.create(&rule("rt poison", &poison_src)).await.expect("poison rule");
    let nul = repo.create(&rule("rt nul", &nul_src)).await.expect("nul rule");
    let control = repo.create(&rule("rt control", &control_src)).await.expect("control rule");

    let mv_gen = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());
    let mut mvs = Vec::new();
    for r in [&poison, &nul, &control] {
        mvs.push(mv_gen.create_view(r).await.expect("create MV"));
    }

    // Separate inserts, in queue order: poison, then NUL, then control.
    let ch = dual_pool.clickhouse().clone();
    insert_events(&ch, &poison_src, 1, &format!("'{POISON_MARKER} {{i}}'")).await;
    insert_events(&ch, &nul_src, 1, "concat('p', char(0), 'q {i}')").await;
    insert_events(&ch, &control_src, 3, "'nan5428 control {i}'").await;
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
    let started = Instant::now();
    let handle = processor.start().await.expect("start processor");

    let mut control_alerts = Vec::new();
    while started.elapsed() < CONTROL_DEADLINE {
        control_alerts = alerts(&pg, control.id).await;
        if control_alerts.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let control_latency = started.elapsed();
    // A moment for anything that would (wrongly) still land.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let poison_alerts = alerts(&pg, poison.id).await;
    let poison_gaps = gaps(&pg, poison.id).await;
    let nul_alerts = alerts(&pg, nul.id).await;
    let nul_gaps = gaps(&pg, nul.id).await;
    let control_gaps = gaps(&pg, control.id).await;

    processor.stop();
    handle.abort();
    let admin_ch = dual_pool.clickhouse_admin().clone();
    for mv in &mvs {
        let _ = admin_ch.query(&format!("DROP VIEW IF EXISTS {mv}")).execute().await;
    }
    pg.close().await;
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)")))
        .execute(&admin)
        .await;

    eprintln!(
        "control alerts: {} after {:?}; poison gaps: {:?}; nul alerts: {}",
        control_alerts.len(),
        control_latency,
        poison_gaps,
        nul_alerts.len()
    );
    assert_eq!(
        control_alerts.len(),
        3,
        "control rule must alert within {CONTROL_DEADLINE:?} despite the poison signal ahead of it"
    );
    assert_eq!(poison_alerts.len(), 1, "a minimal reference alert replaces the unwritable one");
    let reference = poison_alerts[0].to_string();
    assert!(reference.contains("_nano_unstored_event"), "{reference}");
    assert!(!reference.contains(POISON_MARKER), "no event content: {reference}");
    assert_eq!(poison_gaps.len(), 1, "the dropped poison signal is one coverage gap");
    assert_eq!(poison_gaps[0].0, 1, "a data error is dead-lettered on its first attempt");
    assert!(
        poison_gaps[0].1.contains("dropped after 1 attempt(s) (pg:22023)"),
        "{}",
        poison_gaps[0].1
    );
    assert!(poison_gaps[0].1.starts_with("[data]"), "{}", poison_gaps[0].1);
    assert_eq!(nul_alerts.len(), 1, "the U+0000 event alerts once sanitized");
    let nul_text = nul_alerts[0].to_string();
    assert!(nul_text.contains("p\u{FFFD}q"), "{nul_text}");
    assert!(nul_gaps.is_empty() && control_gaps.is_empty());
}

/// A systemic fault (every signal of the rule fails with the same
/// unrecognised SQLSTATE) must not drop signals at full speed: after
/// `SYSTEMIC_BREAKER_THRESHOLD` dead-letters the processor holds and marks the
/// rule failing, which detection health reports as critical.
#[tokio::test]
#[ignore = "needs disposable PG + CH (see module docs)"]
async fn systemic_failure_trips_the_breaker_and_raises_health() {
    let env = env();
    let (pg, pg_url, admin) = scratch_db(&env).await;
    let dual_pool = dual_pool(&env, &pg_url).await;

    sqlx::query(
        "INSERT INTO signal_processor_watermarks (id, last_inserted_at, last_signal_id, processed_count, updated_at)
         VALUES ('default', NOW(), NULL, 0, NOW())
         ON CONFLICT (id) DO UPDATE SET last_inserted_at = NOW(), last_signal_id = NULL",
    )
    .execute(&pg)
    .await
    .expect("seed watermark");
    // SQLSTATE 42501 (insufficient privilege): not data, not transient.
    sqlx::query(
        r#"
        CREATE FUNCTION nan5428_systemic() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'nan5428 injected systemic error' USING ERRCODE = '42501';
        END $$;
        "#,
    )
    .execute(&pg)
    .await
    .expect("systemic function");
    sqlx::query(
        "CREATE TRIGGER nan5428_systemic BEFORE INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION nan5428_systemic()",
    )
    .execute(&pg)
    .await
    .expect("systemic trigger");

    let tag = format!("{:x}", Utc::now().timestamp_micros());
    let src = format!("nan5428s{tag}");
    let repo = DetectionRuleRepository::new(pg.clone());
    let systemic = repo.create(&rule("rt systemic", &src)).await.expect("systemic rule");
    let mv_gen = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());
    let mv = mv_gen.create_view(&systemic).await.expect("create MV");

    let ch = dual_pool.clickhouse().clone();
    insert_events(&ch, &src, 6, "'nan5428 systemic {i}'").await;
    tokio::time::sleep(Duration::from_secs(7)).await;

    let processor = SignalProcessor::new(
        dual_pool.clone(),
        SignalProcessorConfig { poll_interval_ms: 300, batch_size: 100, ..SignalProcessorConfig::default() },
    );
    let handle = processor.start().await.expect("start processor");

    // 3 signals x 3 attempts (2s + 4s backoff each), then the hold.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut failing: (i16, i64) = (0, 0);
    while Instant::now() < deadline {
        failing = sqlx::query_as(
            "SELECT consecutive_failures, (SELECT count(*) FROM detection_coverage_gaps g WHERE g.rule_id = r.id) \
             FROM detection_rules r WHERE id = $1",
        )
        .bind(systemic.id)
        .fetch_one(&pg)
        .await
        .expect("rule state");
        if failing.0 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Held: no further dead-letters while it stays down.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let gaps_after: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_coverage_gaps WHERE rule_id = $1")
        .bind(systemic.id)
        .fetch_one(&pg)
        .await
        .expect("gaps");
    let health = nanosiem_core::detection::health::read_execution_health(&pg).await.expect("health");

    processor.stop();
    handle.abort();
    let _ = dual_pool.clickhouse_admin().query(&format!("DROP VIEW IF EXISTS {mv}")).execute().await;
    pg.close().await;
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)")))
        .execute(&admin)
        .await;

    eprintln!("systemic: consecutive_failures={} gaps={} gaps_after={gaps_after} health={health:?}", failing.0, failing.1);
    assert!(failing.0 > 0, "the held rule is marked failing");
    assert_eq!(gaps_after, 3, "only SYSTEMIC_BREAKER_THRESHOLD signals are dead-lettered, then it holds");
    assert_eq!(health.status, "critical");
}

