// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1710 (audit D13) end-to-end: the real-time pipeline must dedup alerts
//! and findings per (rule, entity, window) for Grouped rules, and keep
//! one-alert-per-signal for PerEvent rules.
//!
//! Drives the REAL pipeline components against the local databases:
//!
//! ```text
//! rule (DetectionRuleRepository) → MV (MaterializedViewGenerator, live CH)
//!   → INSERT nanosiem.logs → MV writes nanosiem.signals
//!   → SignalProcessor (THIS branch's code) → alerts / findings / entity risk
//! ```
//!
//! Isolation: the test creates a scratch Postgres database (rules, alerts,
//! watermark, emission store) so it never touches the dev stack's PG state or
//! races its jobs-node SignalProcessor — that processor sees the test signals
//! in the shared `nanosiem.signals` but skips them as `RuleMissing` (the test
//! rules only exist in the scratch DB). ClickHouse state (synthetic
//! `d13_test_*` log rows, `signals` rows, the MVs, `findings` rows) is cleaned
//! up at the end of the run.
//!
//! Run (requires local PG :5432 with superuser nanosiem/nanosiem and local CH
//! :8123 carrying the `nanosiem` schema):
//!
//! ```bash
//! cargo test -p nanosiem-core --test realtime_window_dedup_e2e -- --ignored --nocapture
//! ```

use chrono::{DateTime, Duration as ChronoDuration, DurationRound, Utc};
use nanosiem_core::db::repository::DetectionRuleRepository;
use nanosiem_core::db::{run_postgres_migrations, DualPool, DualPoolConfig};
use nanosiem_core::detection::{MaterializedViewGenerator, SignalProcessor, SignalProcessorConfig};
use nanosiem_core::models::{AlertMode, DetectionMode, NewDetectionRule, RuleMode, Severity};
use sqlx::PgPool;
use std::time::{Duration, Instant};
use uuid::Uuid;

const ADMIN_PG_URL: &str = "postgres://nanosiem:nanosiem@localhost:5432/nanosiem";
const SCRATCH_DB: &str = "nanosiem_d13_e2e";
const CH_URL: &str = "http://localhost:8123";
const GROUPED_SOURCE: &str = "d13_test_grouped";
const PEREVENT_SOURCE: &str = "d13_test_perevent";

/// How long to wait for the async pipeline (MV insert visibility + the
/// processor's 5s watermark settling lag + poll interval) before a phase is
/// declared stuck.
const PHASE_TIMEOUT: Duration = Duration::from_secs(60);

fn new_realtime_rule(name: &str, source: &str, alert_mode: AlertMode) -> NewDetectionRule {
    NewDetectionRule {
        name: name.to_string(),
        description: Some("NAN-1710 D13 e2e".to_string()),
        query: format!("source_type=\"{source}\""),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Alerting),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: None,
        realtime_enabled: Some(true),
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(75),
        risk_entity_field: Some("src_ip".to_string()),
        risk_modifiers: None,
        lookback_minutes: None,
        dataset: None,
        auto_tuning_enabled: Some(false),
        auto_tuning_min_confidence: None,
        auto_tuning_critical: None,
        ai_triage_hints: None,
        folder: None,
        case_visibility: None,
        case_group_ids: None,
        case_assigned_group: None,
        alert_mode: Some(alert_mode),
        playbook_selector_mode: None,
        playbook_id: None,
        source_path: None,
        source_repo_url: None,
    }
}

/// Insert `n` synthetic events for one entity into the live `nanosiem.logs`,
/// spread 1s apart from `base` (keep n ≤ 50 so a mid-minute base stays inside
/// one 60s dedup bucket). Distinct ids + messages so the per-alert
/// `event_hash` NEVER collides — the only thing that can dedup Grouped alerts
/// here is the D13 (rule, entity, window) emission store.
async fn insert_events(
    ch: &clickhouse::Client,
    source_type: &str,
    src_ip: &str,
    base: DateTime<Utc>,
    n: usize,
    label: &str,
) -> Result<(), String> {
    let rows: Vec<String> = (0..n)
        .map(|i| {
            let ts = (base + ChronoDuration::seconds(i as i64))
                .format("%Y-%m-%d %H:%M:%S%.6f")
                .to_string();
            format!(
                "(generateUUIDv4(), toDateTime64('{ts}', 6), '{source_type}', 'd13 {label} evt {i}', '{src_ip}')"
            )
        })
        .collect();
    let sql = format!(
        "INSERT INTO nanosiem.logs (id, timestamp, source_type, message, src_ip) VALUES {}",
        rows.join(", ")
    );
    ch.clone()
        // Synchronous insert so the MV fires before we start waiting
        // (async_insert buffering would add its own flush latency).
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .query(&sql)
        .execute()
        .await
        .map_err(|e| format!("insert {n} {label} events: {e}"))
}

/// Poll `sql` (must select a single BIGINT, $1 = rule id) until it reaches
/// `at_least`, then return the value. Errors out with diagnostics on timeout.
async fn wait_at_least(
    pool: &PgPool,
    sql: &str,
    rule_id: Uuid,
    at_least: i64,
    what: &str,
) -> Result<i64, String> {
    let start = Instant::now();
    let mut last = -1;
    while start.elapsed() < PHASE_TIMEOUT {
        last = sqlx::query_scalar::<_, i64>(sql)
            .bind(rule_id)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("poll {what}: {e}"))?;
        if last >= at_least {
            return Ok(last);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "timed out waiting for {what} >= {at_least} (last seen: {last})"
    ))
}

async fn alert_count(pool: &PgPool, rule_id: Uuid) -> Result<i64, String> {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM alerts WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count alerts: {e}"))
}

async fn emission_count(pool: &PgPool, rule_id: Uuid) -> Result<i64, String> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM detection_finding_emissions WHERE rule_id = $1",
    )
    .bind(rule_id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count emissions: {e}"))
}

async fn entity_signal_count(pool: &PgPool, entity: &str) -> Result<i64, String> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(sum(signal_count), 0)::bigint FROM entity_risk_scores WHERE entity = $1",
    )
    .bind(entity)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("entity risk for {entity}: {e}"))
}

fn ensure(cond: bool, msg: String) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg) }
}

#[tokio::test]
#[ignore] // Needs the local dev PG (:5432) + CH (:8123); run with -- --ignored.
async fn realtime_grouped_dedups_per_entity_window_per_event_unchanged() {
    // ---- Scratch PG database (fresh migrated schema, isolated watermark) ----
    let admin = PgPool::connect(ADMIN_PG_URL)
        .await
        .expect("connect local Postgres (is the dev stack up?)");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        .execute(&admin)
        .await
        .expect("drop stale scratch db");
    sqlx::query(&format!("CREATE DATABASE {SCRATCH_DB}"))
        .execute(&admin)
        .await
        .expect("create scratch db");

    let scratch_url = format!("postgres://nanosiem:nanosiem@localhost:5432/{SCRATCH_DB}");
    let pg = PgPool::connect(&scratch_url).await.expect("connect scratch db");
    run_postgres_migrations(&pg).await.expect("migrate scratch db");

    // entity_risk_scores is an enterprise table (stripped from core
    // migrations); create it so the FindingLogger's rollup — the risk surface
    // D13 protects from inflation — is observable. Shape mirrors
    // migrations/postgres-enterprise/9000002 (+ the (entity, entity_type)
    // uniqueness its ON CONFLICT upsert requires).
    sqlx::query(
        r#"
        CREATE TABLE entity_risk_scores (
            id serial PRIMARY KEY,
            entity text NOT NULL,
            entity_type text NOT NULL DEFAULT 'unknown',
            risk_score integer NOT NULL DEFAULT 0,
            signal_count integer NOT NULL DEFAULT 0,
            last_signal_at timestamptz,
            first_signal_at timestamptz,
            last_rule_name text,
            last_severity text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            cleared_at timestamptz,
            UNIQUE (entity, entity_type)
        )
        "#,
    )
    .execute(&pg)
    .await
    .expect("create entity_risk_scores");

    // ---- DualPool: scratch PG + the LIVE local ClickHouse ----
    let config = DualPoolConfig::with_auth(scratch_url.clone(), CH_URL, "nanosiem", "default", "");
    let dual_pool = DualPool::new(&config).await.expect("dual pool");

    // Start the watermark at NOW so the processor only drains signals this test
    // creates (never a historical backlog).
    sqlx::query(
        r#"
        INSERT INTO signal_processor_watermarks
            (id, last_inserted_at, last_signal_id, processed_count, updated_at)
        VALUES ('default', NOW(), NULL, 0, NOW())
        ON CONFLICT (id) DO UPDATE SET
            last_inserted_at = NOW(), last_signal_id = NULL, updated_at = NOW()
        "#,
    )
    .execute(&pg)
    .await
    .expect("seed watermark");

    // ---- Rules + their real-time MVs (the REAL generator, on live CH) ----
    let rule_repo = DetectionRuleRepository::new(pg.clone());
    let grouped = rule_repo
        .create(&new_realtime_rule("d13 e2e grouped", GROUPED_SOURCE, AlertMode::Grouped))
        .await
        .expect("create grouped rule");
    let per_event = rule_repo
        .create(&new_realtime_rule("d13 e2e per-event", PEREVENT_SOURCE, AlertMode::PerEvent))
        .await
        .expect("create per-event rule");

    let mv_gen = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());
    let grouped_mv = mv_gen.create_view(&grouped).await.expect("grouped MV");
    let per_event_mv = mv_gen.create_view(&per_event).await.expect("per-event MV");

    // ---- Start THIS branch's SignalProcessor against the shared signals ----
    let processor = SignalProcessor::new(
        dual_pool.clone(),
        SignalProcessorConfig {
            poll_interval_ms: 500,
            ..SignalProcessorConfig::default()
        },
    );
    let handle = processor.start().await.expect("start signal processor");

    // Mid-minute base 2h in the past: every burst below stays inside one 60s
    // dedup bucket, away from bucket boundaries.
    let base = (Utc::now() - ChronoDuration::hours(2))
        .duration_trunc(ChronoDuration::minutes(1))
        .expect("truncate to minute")
        + ChronoDuration::seconds(5);

    let ch = dual_pool.clickhouse().clone();
    let match_count_sql = "SELECT match_count FROM detection_rules WHERE id = $1";

    let phases: Result<(), String> = async {
        // ---- Phase 1: Grouped burst — 5 signals, ONE entity, ONE window ----
        insert_events(&ch, GROUPED_SOURCE, "10.0.0.9", base, 5, "p1").await?;
        // All 5 signals accounted for (alerted or window-deduped)...
        wait_at_least(&pg, match_count_sql, grouped.id, 5, "grouped match_count").await?;
        // ...but exactly ONE grouped alert / emission / finding.
        let alerts = alert_count(&pg, grouped.id).await?;
        ensure(alerts == 1, format!("phase 1: expected 1 grouped alert for a 5-signal burst, got {alerts}"))?;
        let emissions = emission_count(&pg, grouped.id).await?;
        ensure(emissions == 1, format!("phase 1: expected 1 emission, got {emissions}"))?;
        let risk = entity_signal_count(&pg, "10.0.0.9").await?;
        ensure(risk == 1, format!("phase 1: expected entity risk signal_count 1 for 10.0.0.9, got {risk}"))?;

        // ---- Phase 2: DIFFERENT entity, same window → its own alert ----
        insert_events(&ch, GROUPED_SOURCE, "10.0.0.10", base, 3, "p2").await?;
        wait_at_least(&pg, match_count_sql, grouped.id, 8, "grouped match_count").await?;
        let alerts = alert_count(&pg, grouped.id).await?;
        ensure(alerts == 2, format!("phase 2: expected a 2nd alert for the new entity, got {alerts}"))?;
        let risk = entity_signal_count(&pg, "10.0.0.10").await?;
        ensure(risk == 1, format!("phase 2: expected entity risk signal_count 1 for 10.0.0.10, got {risk}"))?;

        // ---- Phase 3: SAME entity, genuinely LATER window → re-emits ----
        insert_events(&ch, GROUPED_SOURCE, "10.0.0.9", base + ChronoDuration::minutes(2), 4, "p3").await?;
        wait_at_least(&pg, match_count_sql, grouped.id, 12, "grouped match_count").await?;
        let alerts = alert_count(&pg, grouped.id).await?;
        ensure(alerts == 3, format!("phase 3: expected a 3rd alert for the later window, got {alerts}"))?;
        let emissions = emission_count(&pg, grouped.id).await?;
        ensure(emissions == 3, format!("phase 3: expected 3 emissions total, got {emissions}"))?;
        // One finding per (entity, window): 10.0.0.9 has two windows → 2.
        let risk = entity_signal_count(&pg, "10.0.0.9").await?;
        ensure(risk == 2, format!("phase 3: expected entity risk signal_count 2 for 10.0.0.9, got {risk}"))?;

        // ---- Phase 4: PerEvent rule — N signals → N alerts (unchanged) ----
        insert_events(&ch, PEREVENT_SOURCE, "10.0.0.99", base, 5, "p4").await?;
        wait_at_least(&pg, match_count_sql, per_event.id, 5, "per-event match_count").await?;
        // Findings land right after the last alert; wait on the risk rollup.
        // (The `$1::uuid IS NOT NULL` tail only satisfies `wait_at_least`'s
        // rule-id bind — the filter itself is the literal entity.)
        let risk_sql =
            "SELECT COALESCE(sum(signal_count), 0)::bigint FROM entity_risk_scores WHERE entity = '10.0.0.99' AND $1::uuid IS NOT NULL";
        wait_at_least(&pg, risk_sql, per_event.id, 5, "per-event entity risk").await?;
        let alerts = alert_count(&pg, per_event.id).await?;
        ensure(alerts == 5, format!("phase 4: expected 5 per-event alerts, got {alerts}"))?;
        let emissions = emission_count(&pg, per_event.id).await?;
        ensure(emissions == 0, format!("phase 4: per-event rules must not use the emission store, got {emissions}"))?;

        Ok(())
    }
    .await;

    // ---- Teardown (always, even when a phase failed) ----
    processor.stop();
    handle.abort();

    let admin_ch = dual_pool.clickhouse_admin().clone();
    for (mv, what) in [(&grouped_mv, "grouped MV"), (&per_event_mv, "per-event MV")] {
        if let Err(e) = admin_ch.query(&format!("DROP VIEW IF EXISTS {mv}")).execute().await {
            eprintln!("cleanup: drop {what}: {e}");
        }
    }
    // Findings are fire-and-forget async inserts (R6) — they can flush AFTER a
    // single cleanup DELETE runs. Sweep in a short retry loop until no test
    // rows remain (or attempts are exhausted, in which case the leftovers are
    // reported for manual cleanup).
    let leftover_filter = format!(
        "source_type IN ('{GROUPED_SOURCE}', '{PEREVENT_SOURCE}') \
         OR (source_type = 'findings' AND rule_id IN ('{}', '{}'))",
        grouped.id, per_event.id
    );
    let cleanup_sql = [
        format!(
            "ALTER TABLE nanosiem.signals DELETE WHERE rule_id IN ('{}', '{}') SETTINGS mutations_sync = 1",
            grouped.id, per_event.id
        ),
        format!(
            "ALTER TABLE nanosiem.logs DELETE WHERE {leftover_filter} SETTINGS mutations_sync = 1"
        ),
    ];
    let mut leftovers: u64 = u64::MAX;
    for attempt in 0..6 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        for sql in &cleanup_sql {
            if let Err(e) = admin_ch.query(sql).execute().await {
                eprintln!("cleanup: {sql}: {e}");
            }
        }
        leftovers = admin_ch
            .query(&format!(
                "SELECT count() FROM nanosiem.logs WHERE {leftover_filter}"
            ))
            .fetch_one::<u64>()
            .await
            .unwrap_or(u64::MAX);
        if leftovers == 0 {
            break;
        }
    }
    if leftovers != 0 {
        eprintln!(
            "cleanup: {leftovers} test rows remain in nanosiem.logs (filter: {leftover_filter})"
        );
    }

    pg.close().await;
    if let Err(e) = sqlx::query(&format!("DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        .execute(&admin)
        .await
    {
        eprintln!("cleanup: drop scratch db: {e}");
    }
    admin.close().await;

    if let Err(msg) = phases {
        panic!("D13 e2e failed: {msg}");
    }
}
