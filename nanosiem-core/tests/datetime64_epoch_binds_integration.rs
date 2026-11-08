// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4938: an integer bound into a `DateTime64` column is read as SECONDS by
//! ClickHouse. Every writer that bound an epoch-millis (or micros) value
//! straight into a `DateTime64` column therefore stored 9999-12-31 (millis are
//! clamped) or failed with DECIMAL_OVERFLOW (micros). These suites drive the
//! REAL writers against a live ClickHouse and assert the stored timestamp is
//! "now", not the far future:
//!
//! - OCSF Detection Finding (`ocsf_logs_raw` → `ocsf_logs.timestamp`)
//! - UDM finding (`logs.timestamp` / `logs.ingest_time`, DateTime64(6))
//! - OCSF audit mirror (`ocsf_logs_raw`, source_type='audit')
//! - identity soft-delete tombstones (`user_registry` DateTime64(3) columns)
//! - synthetic check results (`synthetic_check_results.timestamp`)
//! - IP enrichment tombstones (`ip_enrichments.updated_at`, the
//!   ReplacingMergeTree version: a 9999 tombstone would win forever)
//!
//! `#[ignore]`d live suite — run against a disposable PostgreSQL + ClickHouse
//! migrated with this tree (`NANO_SCHEMA_PROFILE=ocsf`, which also creates the
//! UDM `logs` table):
//! `DATABASE_URL=… NANOSIEM_TEST_CLICKHOUSE_URL=… NANOSIEM_TEST_CLICKHOUSE_USER=…
//!  NANOSIEM_TEST_CLICKHOUSE_PASSWORD=… CLICKHOUSE_RAWSQL_PASSWORD=…
//!  CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=… cargo test -p nanosiem-core
//!  --test datetime64_epoch_binds_integration -- --ignored --test-threads=1`

use chrono::{Duration, Utc};
use nanosiem_core::audit::{AuditEmitter, AuditEvent, AuditSource};
use nanosiem_core::db::dual_pool::{DualPool, DualPoolConfig};
use nanosiem_core::detection::findings::{FindingEvent, FindingLogger};
use nanosiem_core::detection::risk::{score_rule_match, ScoreCalculator};
use nanosiem_core::enrichment::repository::EnrichmentRepository;
use nanosiem_core::enrichment::service::EnrichmentService;
use nanosiem_core::identity::IdentityRepository;
use nanosiem_core::models::detection_rule::{AiTriageHints, DetectionMode};
use nanosiem_core::models::{AlertMode, DetectionRule, RuleMode, Severity};
use nanosiem_core::observability::synthetic_runner::record_result;
use serde_json::json;
use uuid::Uuid;

/// The writers resolve the schema profile from the environment at call (or
/// construction) time; serialize the tests that flip it.
static PROFILE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set for this live suite"))
}

async fn dual_pool() -> DualPool {
    let mut config = DualPoolConfig::with_auth(
        env("DATABASE_URL"),
        env("NANOSIEM_TEST_CLICKHOUSE_URL"),
        "nanosiem",
        env("NANOSIEM_TEST_CLICKHOUSE_USER"),
        env("NANOSIEM_TEST_CLICKHOUSE_PASSWORD"),
    );
    // The raw-SQL feature identities are required at boot (NAN-2001).
    config.clickhouse_rawsql_password = Some(env("CLICKHOUSE_RAWSQL_PASSWORD"));
    config.clickhouse_rawsql_noaudit_password = Some(env("CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD"));
    DualPool::new(&config).await.expect("connect PG + ClickHouse")
}

fn set_profile(profile: &str) {
    std::env::set_var("NANO_SCHEMA_PROFILE", profile);
}

/// Seconds between `expr` (a DateTime64 expression over `from`) and now; the
/// broken writers stored 9999-12-31, i.e. a hugely negative value here.
async fn age_secs(dp: &DualPool, sql: &str) -> Vec<i64> {
    // ClickHouse may still be flushing an async insert; poll briefly.
    for _ in 0..40 {
        let rows: Vec<i64> = dp.clickhouse().query(sql).fetch_all().await.expect(sql);
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no rows for: {sql}");
}

fn assert_recent(ages: &[i64], what: &str) {
    for age in ages {
        assert!(
            (-120..=600).contains(age),
            "{what}: stored timestamp is {age}s from now (9999-12-31 clamp is the NAN-4938 bug)"
        );
    }
}

fn rule() -> DetectionRule {
    DetectionRule {
        id: Uuid::now_v7(),
        name: format!("nan4938-{}", Uuid::new_v4().simple()),
        description: None,
        query: "user=admin".to_string(),
        severity: Severity::High,
        mitre_tactics: vec![],
        mitre_techniques: vec![],
        schedule_cron: None,
        mode: RuleMode::Alerting,
        narrative: None,
        reference_url: None,
        author: None,
        tags: vec![],
        ai_generated: false,
        realtime_enabled: false,
        detection_mode: DetectionMode::Scheduled,
        materialized_view_name: None,
        risk_score: Some(50),
        risk_entity_field: Some("user".to_string()),
        risk_modifiers: sqlx::types::Json(vec![]),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_run_at: None,
        last_match_at: None,
        match_count: 0,
        live_match_count: 0,
        archived: false,
        folder: None,
        ai_triage_hints: sqlx::types::Json(AiTriageHints::default()),
        lookback_minutes: None,
        dataset: None,
        auto_tuning_enabled: true,
        auto_tuning_min_confidence: 0.8,
        auto_tuning_critical: false,
        auto_tuning_disabled_until: None,
        case_visibility: "private".to_string(),
        case_assigned_group: None,
        alert_mode: AlertMode::default(),
        next_run_at: None,
        claimed_by: None,
        claimed_at: None,
        playbook_selector_mode: "none".to_string(),
        playbook_id: None,
        source_path: None,
        source_repo_url: None,
        kind: "standard".to_string(),
        alert_cooldown_minutes: None,
    }
}

fn finding(rule: &DetectionRule) -> FindingEvent {
    let events = vec![json!({"user": "admin", "src_ip": "10.0.0.9"})];
    let risk = score_rule_match(&ScoreCalculator::new(), rule, &events, 1.0);
    FindingEvent::detection_match(rule, &events, false, risk)
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn ocsf_finding_is_dated_now() {
    let _guard = PROFILE.lock().await;
    set_profile("ocsf");
    let dp = dual_pool().await;
    let rule = rule();
    FindingLogger::with_dual_pool(&dp)
        .log_finding(&finding(&rule))
        .await
        .expect("OCSF finding insert");
    let ages = age_secs(
        &dp,
        &format!(
            "SELECT toInt64(dateDiff('second', timestamp, now64(3))) FROM nanosiem.ocsf_logs \
             WHERE source_type = 'findings' \
               AND JSONExtractString(toString(unmapped), 'rule_id') = '{}'",
            rule.id
        ),
    )
    .await;
    assert_recent(&ages, "ocsf_logs.timestamp (finding)");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn udm_finding_inserts_and_is_dated_now() {
    let _guard = PROFILE.lock().await;
    set_profile("udm");
    let dp = dual_pool().await;
    let rule = rule();
    let result = FindingLogger::with_dual_pool(&dp).log_finding(&finding(&rule)).await;
    set_profile("ocsf");
    // Before NAN-4938 this failed outright: epoch-micros read as seconds
    // overflows DateTime64(6) (DECIMAL_OVERFLOW).
    result.expect("UDM finding insert");
    let ages = age_secs(
        &dp,
        &format!(
            "SELECT arrayJoin([toInt64(dateDiff('second', timestamp, now64(6))), \
                               toInt64(dateDiff('second', ingest_time, now64(6)))]) \
             FROM nanosiem.logs WHERE source_type = 'findings' AND rule_id = '{}'",
            rule.id
        ),
    )
    .await;
    assert_recent(&ages, "logs.timestamp / logs.ingest_time (finding)");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn ocsf_audit_mirror_is_dated_now() {
    let _guard = PROFILE.lock().await;
    set_profile("ocsf");
    let dp = dual_pool().await;
    let marker = format!("nan4938-audit-{}", Uuid::new_v4().simple());
    let event = AuditEvent::builder(AuditSource::Detection, "rule_created")
        .resource("detection_rule", None, Some(marker.clone()))
        .build();
    AuditEmitter::new(dp.clone())
        .emit_durable(&event)
        .await
        .expect("audit emit");
    let ages = age_secs(
        &dp,
        &format!(
            "SELECT toInt64(dateDiff('second', timestamp, now64(3))) FROM nanosiem.ocsf_logs \
             WHERE source_type = 'audit' AND JSONExtractString(toString(unmapped), 'resource_name') = '{marker}'"
        ),
    )
    .await;
    assert_recent(&ages, "ocsf_logs.timestamp (audit mirror)");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn identity_tombstones_keep_real_timestamps() {
    let dp = dual_pool().await;
    let ch = dp.clickhouse().clone();
    let provider = format!("nan4938-{}", Uuid::new_v4().simple());
    let signed_in_ms = (Utc::now() - Duration::days(3)).timestamp_millis();
    let synced_ms = (Utc::now() - Duration::days(1)).timestamp_millis();
    ch.query(
        "INSERT INTO nanosiem.user_registry \
         (provider_id, external_id, username, last_sign_in_at, last_synced_at, version) \
         VALUES (?, 'u1', 'alice', fromUnixTimestamp64Milli(toInt64(?), 'UTC'), \
                 fromUnixTimestamp64Milli(toInt64(?), 'UTC'), 1)",
    )
    .bind(&provider)
    .bind(signed_in_ms)
    .bind(synced_ms)
    .execute()
    .await
    .expect("seed user_registry");

    let repo = IdentityRepository::new_with_clickhouse(dp.postgres().clone(), ch.clone());
    let marked = repo
        .mark_absent_users_by_sync_time(&provider, Utc::now())
        .await
        .expect("mark absent");
    assert_eq!(marked, 1);

    let rows: Vec<(i64, i64, String)> = ch
        .query(
            "SELECT toInt64(dateDiff('second', last_synced_at, now64(3))), \
                    toUnixTimestamp64Milli(last_sign_in_at), account_status \
             FROM nanosiem.user_registry FINAL WHERE provider_id = ?",
        )
        .bind(&provider)
        .fetch_all()
        .await
        .expect("read tombstone");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (synced_age, sign_in_ms, status) = &rows[0];
    assert_eq!(status, "deleted");
    assert_recent(&[*synced_age], "user_registry.last_synced_at (tombstone)");
    assert_eq!(*sign_in_ms, signed_in_ms, "last_sign_in_at must carry forward unchanged");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn synthetic_result_is_dated_now() {
    let dp = dual_pool().await;
    let check = Uuid::now_v7();
    record_result(dp.clickhouse(), check, Utc::now().timestamp_millis(), 1, 12.5, 200, "")
        .await
        .expect("record result");
    let ages = age_secs(
        &dp,
        &format!(
            "SELECT toInt64(dateDiff('second', timestamp, now64(3))) \
             FROM nanosiem.synthetic_check_results WHERE check_id = '{check}'"
        ),
    )
    .await;
    assert_recent(&ages, "synthetic_check_results.timestamp");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn ip_enrichment_tombstone_is_dated_now() {
    let dp = dual_pool().await;
    let ch = dp.clickhouse().clone();
    let source = format!("nan4938-{}", Uuid::new_v4().simple());
    ch.query(
        "INSERT INTO nanosiem.ip_enrichments (network, source_id, country, updated_at, deleted) \
         VALUES ('198.51.100.0/24', ?, 'NL', now64(3) - INTERVAL 1 HOUR, 0)",
    )
    .bind(&source)
    .execute()
    .await
    .expect("seed ip_enrichments");

    let service = EnrichmentService::with_defaults(EnrichmentRepository::new(dp.postgres().clone()))
        .with_clickhouse(ch.clone());
    service
        .clear_ip_enrichments_for_source(&source)
        .await
        .expect("tombstone");

    let rows: Vec<(i64, u8)> = ch
        .query(
            "SELECT toInt64(dateDiff('second', updated_at, now64(3))), deleted \
             FROM nanosiem.ip_enrichments WHERE source_id = ? ORDER BY updated_at",
        )
        .bind(&source)
        .fetch_all()
        .await
        .expect("read ip_enrichments");
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (tomb_age, deleted) = rows[1];
    assert_eq!(deleted, 1, "the newest row is the tombstone: {rows:?}");
    // A 9999 tombstone would also outrank every later re-enable forever.
    assert_recent(&[tomb_age], "ip_enrichments.updated_at (tombstone)");
}
