// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4954: security-critical audit events survive a ClickHouse
//! MEMORY_LIMIT_EXCEEDED (code 241).
//!
//! Drives the REAL emitter, outbox and drainer against a live PostgreSQL +
//! ClickHouse. The fault is a genuine server-side 241: the "faulty" pool sends
//! `max_memory_usage=1` with every request of the app identity, so ClickHouse
//! itself refuses the insert exactly as it did under memory pressure in the
//! NAN-4937 browser suite. The "healthy" pool is the same server without the
//! setting, standing in for ClickHouse after recovery.
//!
//! `#[ignore]`d live suite — run against a DISPOSABLE PostgreSQL + ClickHouse
//! migrated with this tree under `NANO_SCHEMA_PROFILE=ocsf` (which also creates
//! the UDM `logs` table):
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=… NANOSIEM_TEST_CLICKHOUSE_URL=…
//!  NANOSIEM_TEST_CLICKHOUSE_USER=… NANOSIEM_TEST_CLICKHOUSE_PASSWORD=…
//!  CLICKHOUSE_RAWSQL_PASSWORD=… CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=…
//!  cargo test -p nanosiem-core --test audit_outbox_durability_integration
//!  -- --ignored --test-threads=1`

mod common;

use std::sync::Arc;

use nanosiem_core::audit::outbox_drain::BACKLOG_HEALTH_DEDUP_KEY;
use nanosiem_core::audit::{
    AuditEmitter, AuditEvent, AuditOutboxDrainer, AuditSource, ClickHouseAuditQuery,
    DurableOutcome, APIKEY_CREATED, APIKEY_DELETED, LOGIN_SUCCESS,
};
use nanosiem_core::auth::{ApiKeyRepository, ApiKeyService, CreateApiKeyRequest};
use nanosiem_core::db::dual_pool::{DualPool, DualPoolConfig};
use nanosiem_core::db::repository::RateLimitRepository;
use nanosiem_core::siem_health::analyzer::audit_durability_recommendations;
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set for this live suite"))
}

/// Healthy pool over the migrated test databases. Fails fast if the target
/// ClickHouse is not answering (never silently points at someone else's).
async fn healthy_pool() -> DualPool {
    std::env::set_var("NANO_SCHEMA_PROFILE", "ocsf");
    // Apply PG migrations (and enforce the destructive-test opt-in) first.
    common::migrated_pool().await;
    let mut config = DualPoolConfig::with_auth(
        env("DATABASE_URL"),
        env("NANOSIEM_TEST_CLICKHOUSE_URL"),
        "nanosiem",
        env("NANOSIEM_TEST_CLICKHOUSE_USER"),
        env("NANOSIEM_TEST_CLICKHOUSE_PASSWORD"),
    );
    config.clickhouse_rawsql_password = Some(env("CLICKHOUSE_RAWSQL_PASSWORD"));
    config.clickhouse_rawsql_noaudit_password = Some(env("CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD"));
    let dp = DualPool::new(&config).await.expect("connect PG + ClickHouse");
    let one: u8 = dp
        .clickhouse()
        .query("SELECT 1")
        .fetch_one()
        .await
        .expect("test ClickHouse must answer before the suite runs");
    assert_eq!(one, 1);
    dp
}

/// The same server, but every app-identity request carries
/// `max_memory_usage=1`: ClickHouse answers with a real code 241.
fn memory_limited(dp: &DualPool) -> DualPool {
    dp.with_clickhouse_setting("max_memory_usage", "1")
}

fn critical_event(action: &str, marker: &str) -> AuditEvent {
    AuditEvent::builder(AuditSource::Auth, action)
        .actor(Some(Uuid::now_v7()), Some(format!("analyst-{marker}")))
        .resource("user", None, Some(marker.to_string()))
        .client(Some("10.9.8.7".to_string()), Some("nan4954-test".to_string()))
        .build()
}

async fn udm_rows(dp: &DualPool, marker: &str) -> u64 {
    dp.clickhouse()
        .query(
            "SELECT count() FROM logs WHERE source_type = 'audit' \
             AND JSONExtractString(metadata, 'resource_name') = ?",
        )
        .bind(marker)
        .fetch_one()
        .await
        .expect("count UDM audit rows")
}

async fn ocsf_rows(dp: &DualPool, marker: &str) -> u64 {
    dp.clickhouse()
        .query(
            "SELECT count() FROM ocsf_logs WHERE source_type = 'audit' \
             AND JSONExtractString(toString(unmapped), 'resource_name') = ?",
        )
        .bind(marker)
        .fetch_one()
        .await
        .expect("count OCSF audit mirror rows")
}

#[derive(sqlx::FromRow, Debug)]
struct OutboxRow {
    delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    udm_delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    ocsf_delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    attempts: i32,
    last_error: Option<String>,
}

async fn outbox_row(dp: &DualPool, event_id: Uuid) -> OutboxRow {
    sqlx::query_as(
        "SELECT delivered_at, udm_delivered_at, ocsf_delivered_at, attempts, last_error \
         FROM security_audit_events WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_one(dp.postgres())
    .await
    .expect("security-critical event must have a PostgreSQL record")
}

/// Pretend the inline window passed and the row is due now (instead of
/// sleeping 30s+ of backoff in a test).
async fn age_and_make_due(dp: &DualPool, event_id: Uuid) {
    sqlx::query(
        "UPDATE security_audit_events \
         SET created_at = NOW() - INTERVAL '2 minutes', next_attempt_at = NOW() \
         WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(dp.postgres())
    .await
    .expect("age outbox row");
}

async fn active_health_event(dp: &DualPool) -> Option<(String, String)> {
    sqlx::query_as(
        "SELECT severity, summary FROM system_health_events \
         WHERE dedup_key = $1 AND status = 'active'",
    )
    .bind(BACKLOG_HEALTH_DEDUP_KEY)
    .fetch_optional(dp.postgres())
    .await
    .expect("read system_health_events")
}

/// Leave no due rows from other tests for the drainer to pick up.
async fn clear_outbox(dp: &DualPool) {
    sqlx::query("DELETE FROM security_audit_events")
        .execute(dp.postgres())
        .await
        .expect("clear outbox");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn the_fault_is_a_real_clickhouse_memory_limit() {
    let dp = healthy_pool().await;
    let err = memory_limited(&dp)
        .clickhouse()
        .query("SELECT count() FROM numbers(1000000)")
        .fetch_one::<u64>()
        .await
        .expect_err("max_memory_usage=1 must make ClickHouse refuse the query");
    let msg = err.to_string();
    assert!(
        msg.contains("241") || msg.contains("MEMORY_LIMIT_EXCEEDED"),
        "expected MEMORY_LIMIT_EXCEEDED (241), got: {msg}"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn security_event_survives_clickhouse_241_and_drains_after_recovery() {
    let dp = healthy_pool().await;
    clear_outbox(&dp).await;
    let faulty = memory_limited(&dp);
    let marker = format!("nan4954-{}", Uuid::new_v4().simple());
    let event = critical_event(LOGIN_SUCCESS, &marker);

    // 1. ClickHouse refuses with 241: the emit still succeeds, durably, in PG.
    let outcome = AuditEmitter::new(faulty.clone())
        .emit_durable(&event)
        .await
        .expect("a ClickHouse failure must not lose a security-critical event");
    let DurableOutcome::Deferred { clickhouse_error } = &outcome else {
        panic!("expected a deferred delivery, got {outcome:?}");
    };
    assert!(
        clickhouse_error.contains("241") || clickhouse_error.contains("MEMORY_LIMIT_EXCEEDED"),
        "the deferral should carry the real ClickHouse error: {clickhouse_error}"
    );

    let row = outbox_row(&dp, event.event_id).await;
    assert!(row.delivered_at.is_none(), "{row:?}");
    assert_eq!(row.attempts, 1, "{row:?}");
    assert!(row.last_error.as_deref().unwrap_or("").contains("MEMORY_LIMIT_EXCEEDED"), "{row:?}");
    assert_eq!(udm_rows(&dp, &marker).await, 0, "nothing reached ClickHouse yet");

    // 2. The degraded /api/audit read path serves it from PostgreSQL, with
    //    the same caller scoping (actor filter) the handler applies.
    let (entries, total) = AuditEmitter::new(dp.clone())
        .outbox()
        .query(&ClickHouseAuditQuery {
            actor_id: event.actor_id,
            ..Default::default()
        })
        .await
        .expect("PostgreSQL fallback query");
    assert_eq!(total, 1);
    assert_eq!(entries[0].event_id, event.event_id.to_string());
    assert_eq!(entries[0].action.as_deref(), Some(LOGIN_SUCCESS));
    assert_eq!(entries[0].resource_name.as_deref(), Some(marker.as_str()));
    assert_eq!(entries[0].status.as_deref(), Some("success"));

    // 3. While ClickHouse still refuses, the drainer retries, fails, and the
    //    backlog is flagged: system health event + SIEM Health finding.
    age_and_make_due(&dp, event.event_id).await;
    let faulty_drainer = AuditOutboxDrainer::new(
        Arc::new(AuditEmitter::new(faulty.clone())),
        dp.postgres().clone(),
    );
    let stats = faulty_drainer.tick().await.expect("drain tick");
    assert_eq!(stats.overdue, 1, "{stats:?}");
    assert!(stats.is_backlogged());
    assert_eq!(stats.max_attempts, 2, "inline failure + one drainer retry: {stats:?}");
    assert!(stats.last_error.as_deref().unwrap_or("").contains("MEMORY_LIMIT_EXCEEDED"));
    assert_eq!(udm_rows(&dp, &marker).await, 0);

    let (severity, summary) = active_health_event(&dp)
        .await
        .expect("an undelivered backlog must raise a system health event");
    assert_eq!(severity, "high");
    assert!(summary.contains("MEMORY_LIMIT_EXCEEDED"), "{summary}");

    let recs = audit_durability_recommendations(Some(&stats));
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].priority, "high");
    assert!(recs[0].title.contains("not in ClickHouse"), "{}", recs[0].title);

    // 4. ClickHouse recovers: the next drain delivers the event — UDM row AND
    //    OCSF mirror, exactly once — stamps it, and resolves the condition.
    sqlx::query("UPDATE security_audit_events SET next_attempt_at = NOW() WHERE event_id = $1")
        .bind(event.event_id)
        .execute(dp.postgres())
        .await
        .unwrap();
    let healthy_drainer = AuditOutboxDrainer::new(
        Arc::new(AuditEmitter::new(dp.clone())),
        dp.postgres().clone(),
    );
    let stats = healthy_drainer.tick().await.expect("drain tick after recovery");
    assert_eq!(stats.pending, 0, "{stats:?}");
    assert!(!stats.is_backlogged());
    assert_eq!(stats.deferred_24h, 1, "the failure stays visible for 24h: {stats:?}");

    let row = outbox_row(&dp, event.event_id).await;
    assert!(row.delivered_at.is_some() && row.udm_delivered_at.is_some() && row.ocsf_delivered_at.is_some(), "{row:?}");
    assert_eq!(udm_rows(&dp, &marker).await, 1);
    assert_eq!(ocsf_rows(&dp, &marker).await, 1);
    assert!(active_health_event(&dp).await.is_none(), "backlog condition must resolve");

    // The delivered row keeps the event's real time, not the drain time.
    let skew: i64 = dp
        .clickhouse()
        .query(
            "SELECT toInt64(dateDiff('millisecond', timestamp, \
                 fromUnixTimestamp64Milli(toInt64(?), 'UTC'))) FROM logs \
             WHERE source_type = 'audit' AND JSONExtractString(metadata, 'resource_name') = ?",
        )
        .bind(event.occurred_at.timestamp_millis())
        .bind(&marker)
        .fetch_one()
        .await
        .unwrap();
    assert!(skew.abs() <= 1, "UDM row must be dated at occurred_at (skew {skew} ms)");

    // After recovery the medium "failed in the last 24h" finding remains.
    let recs = audit_durability_recommendations(Some(&stats));
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].priority, "medium");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn healthy_emit_is_recorded_and_redrain_never_duplicates() {
    let dp = healthy_pool().await;
    clear_outbox(&dp).await;
    let marker = format!("nan4954-{}", Uuid::new_v4().simple());
    let event = critical_event(APIKEY_CREATED, &marker);
    let emitter = Arc::new(AuditEmitter::new(dp.clone()));

    // Healthy path: delivered inline, and still recorded in PostgreSQL.
    assert_eq!(
        emitter.emit_durable(&event).await.expect("emit"),
        DurableOutcome::Delivered
    );
    let row = outbox_row(&dp, event.event_id).await;
    assert!(row.delivered_at.is_some(), "{row:?}");
    assert_eq!(row.attempts, 0);
    assert_eq!(udm_rows(&dp, &marker).await, 1);

    // Simulate a lost delivery stamp (process died between the ClickHouse ack
    // and the PG update): the drainer must notice the rows already exist.
    sqlx::query(
        "UPDATE security_audit_events SET delivered_at = NULL, udm_delivered_at = NULL, \
         ocsf_delivered_at = NULL, next_attempt_at = NOW() WHERE event_id = $1",
    )
    .bind(event.event_id)
    .execute(dp.postgres())
    .await
    .unwrap();
    let drainer = AuditOutboxDrainer::new(emitter.clone(), dp.postgres().clone());
    let outcome = drainer.drain_once().await.expect("drain");
    assert_eq!(outcome.claimed, 1);
    assert_eq!(outcome.already_present, 1, "{outcome:?}");
    assert_eq!(outcome.already_present_ocsf, 1, "{outcome:?}");
    assert_eq!(outcome.delivered, 1, "{outcome:?}");
    assert_eq!(udm_rows(&dp, &marker).await, 1, "UDM row must not be duplicated");
    assert_eq!(ocsf_rows(&dp, &marker).await, 1, "OCSF mirror must not be duplicated");

    // The mirror row's id IS the event id (what the duplicate check keys on).
    let mirror_id: String = dp
        .clickhouse()
        .query(
            "SELECT toString(id) FROM ocsf_logs WHERE source_type = 'audit' \
             AND JSONExtractString(toString(unmapped), 'resource_name') = ?",
        )
        .bind(&marker)
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(mirror_id, event.event_id.to_string());
}

/// NAN-4954 P1: once `record` returns (the handler path awaits it before
/// responding) the event survives the process dying before ANY ClickHouse
/// attempt: the drainer delivers it from PostgreSQL.
#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn recorded_event_survives_a_crash_before_clickhouse_delivery() {
    let dp = healthy_pool().await;
    clear_outbox(&dp).await;
    let marker = format!("nan4954-{}", Uuid::new_v4().simple());
    let event = critical_event(LOGIN_SUCCESS, &marker);
    let emitter = Arc::new(AuditEmitter::new(dp.clone()));

    emitter.record(&event).await.expect("record");
    // ... process dies here: no deliver_recorded, nothing in ClickHouse.
    assert_eq!(udm_rows(&dp, &marker).await, 0);
    assert_eq!(outbox_row(&dp, event.event_id).await.attempts, 0);

    age_and_make_due(&dp, event.event_id).await;
    let stats = AuditOutboxDrainer::new(emitter, dp.postgres().clone())
        .tick()
        .await
        .expect("drain");
    assert_eq!(stats.pending, 0, "{stats:?}");
    assert_eq!(udm_rows(&dp, &marker).await, 1);
    assert_eq!(ocsf_rows(&dp, &marker).await, 1);
}

fn api_key_service(dp: &DualPool) -> ApiKeyService {
    ApiKeyService::new(
        ApiKeyRepository::new(dp.postgres().clone()),
        RateLimitRepository::new(dp.postgres().clone()),
    )
}

fn key_request(name: &str) -> CreateApiKeyRequest {
    CreateApiKeyRequest {
        name: name.to_string(),
        description: None,
        permissions: vec!["audit:view".to_string()],
        expires_at: None,
        rate_limit: None,
    }
}

async fn api_key_count(dp: &DualPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE name = $1")
        .bind(name)
        .fetch_one(dp.postgres())
        .await
        .unwrap()
}

/// NAN-4954 P1: API-key create and delete commit their audit record in the
/// SAME transaction as the state change — never one without the other.
#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn api_key_lifecycle_records_audit_in_the_same_transaction() {
    let dp = healthy_pool().await;
    clear_outbox(&dp).await;
    let service = api_key_service(&dp);
    let name = format!("nan4954-key-{}", Uuid::new_v4().simple());

    let (created, event) = service
        .create_key_audited(key_request(&name), None, |id, key_name| {
            AuditEvent::builder(AuditSource::ApiKey, APIKEY_CREATED)
                .resource("api_key", Some(id), Some(key_name.to_string()))
                .build()
        })
        .await
        .expect("create");
    assert_eq!(event.resource_id, Some(created.id));
    let row = outbox_row(&dp, event.event_id).await;
    assert!(row.delivered_at.is_none(), "recorded, not yet delivered: {row:?}");

    let delete_event = AuditEvent::builder(AuditSource::ApiKey, APIKEY_DELETED)
        .resource("api_key", Some(created.id), Some(name.clone()))
        .build();
    service.delete_key_audited(created.id, &delete_event).await.expect("delete");
    outbox_row(&dp, delete_event.event_id).await;
    assert_eq!(api_key_count(&dp, &name).await, 0);

    // The audit record cannot be written → the key is NOT created (the
    // failure is explicit and the state change rolls back).
    sqlx::query("ALTER TABLE security_audit_events RENAME TO security_audit_events_n4954_off")
        .execute(dp.postgres())
        .await
        .unwrap();
    let name2 = format!("nan4954-key-{}", Uuid::new_v4().simple());
    let result = service
        .create_key_audited(key_request(&name2), None, |id, key_name| {
            AuditEvent::builder(AuditSource::ApiKey, APIKEY_CREATED)
                .resource("api_key", Some(id), Some(key_name.to_string()))
                .build()
        })
        .await;
    sqlx::query("ALTER TABLE security_audit_events_n4954_off RENAME TO security_audit_events")
        .execute(dp.postgres())
        .await
        .unwrap();
    assert!(result.is_err(), "create must fail when its audit record cannot be written");
    assert_eq!(api_key_count(&dp, &name2).await, 0, "the key must roll back with its record");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL + ClickHouse; run with --ignored"]
async fn event_is_lost_only_when_both_stores_fail() {
    let dp = healthy_pool().await;
    // PostgreSQL unreachable (closed pool) AND ClickHouse refusing: the one
    // case that must surface as an error rather than a silent drop.
    let pg_down = DualPool::clone(&memory_limited(&dp));
    pg_down.postgres().close().await;
    let marker = format!("nan4954-{}", Uuid::new_v4().simple());
    let err = AuditEmitter::new(pg_down)
        .emit_durable(&critical_event(LOGIN_SUCCESS, &marker))
        .await
        .expect_err("both stores failing must be an explicit error");
    let msg = err.to_string();
    assert!(msg.contains("PostgreSQL") && msg.contains("ClickHouse"), "{msg}");
}
