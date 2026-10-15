// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3499 (the lean load-test tenant, 2026-10-10): 56 findings the detect[T]
//! drain had acknowledged on 10-07 (risk and event both stamped with one
//! `parts:<seq>:<sha>` head, ~1 s after creation) still showed
//! `published_at IS NULL`, because that composite stamp waited for a gen1
//! serving generation a lean tenant never has. The gen1-only retention
//! (lake_risk_publish) keys on it too, so lean outboxes were never pruned.
//!
//! Covers, on the lean drain path with a tenant-bound RLS principal:
//! * a pass that fails after claiming leaves its rows pending, records the
//!   attempt and error, and the next pass publishes and completes them;
//! * a lean acknowledgement sets `published_at` (core migration 346, formerly 344), gen1
//!   component acks still do not, and 344 backfills rows acked before it;
//! * the drain prunes only its tenant's delivered rows past retention.
//!
//! Run against a disposable PostgreSQL server with NANO_RISK_TEST_PG set to
//! its loopback administrator URL (`postgres://postgres@127.0.0.1:<port>/risktest`).

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_gate::{FindingGate, FindingGateConfig};
use nanosiem_lake_worker::part_ingest::finding_outbox::{drain_pass, drain_pass_cached, DrainLogCache};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, FindingAppendContext, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::part_log::LocalObjectStore;
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sqlx::postgres::PgPoolOptions;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

const A: &str = "00000000-0000-4000-8000-00000000004a";
const B: &str = "00000000-0000-4000-8000-00000000004b";
const DB: &str = "risktest_lean_finding_retry";
const ROLE: &str = "lean_finding_retry_a";
const MIGRATION_346: &str = include_str!("../../migrations/postgres/346_lean_finding_outbox_completion.sql");

struct GateAppend {
    gate: FindingGate,
    ingestor: &'static tokio::sync::Mutex<Ingestor<'static>>,
    context: FindingAppendContext<'static>,
}

#[async_trait]
impl FindingAppendTransport for GateAppend {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        let request = FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
            parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
        };
        let admitted = self.gate.admit()?;
        self.gate.append(admitted, self.ingestor, &self.context, request, || chrono::Utc::now().timestamp_millis()).await
    }
}

/// The owner refused the append (an expired bearer, a moved epoch): the
/// receipt objects exist but nothing reached the part log.
struct RefusingTransport(AtomicU32);

#[async_trait]
impl FindingAppendTransport for RefusingTransport {
    async fn submit(&self, _: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        self.0.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("injected owner refusal: bearer expired")
    }
}

const TABLE: &str = "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, \
    finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), \
    published_at timestamptz, published_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, \
    risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, \
    generation_published_at timestamptz, serving_generation_id text, PRIMARY KEY (security_tenant_id, tenant_id, finding_id))";

/// The 291 trigger function (gen1 composite only), as before 344.
const GEN1_ONLY_COMPOSITE: &str = "CREATE FUNCTION enforce_detection_lake_composite_ack() RETURNS trigger LANGUAGE plpgsql AS $$ \
    BEGIN IF NEW.risk_published_at IS NOT NULL AND NEW.event_published_at IS NOT NULL AND NEW.generation_published_at IS NOT NULL THEN \
    NEW.published_at := COALESCE(NEW.published_at, NOW()); NEW.published_snapshot_id := NEW.serving_generation_id; \
    ELSE NEW.published_at := NULL; NEW.published_snapshot_id := NULL; END IF; RETURN NEW; END; $$";

async fn setup(admin_url: &str) -> (sqlx::PgPool, sqlx::PgPool, sqlx::PgPool) {
    let server = PgPoolOptions::new().max_connections(1).connect(admin_url).await.unwrap();
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
    sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE ROLE {ROLE} LOGIN")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {DB}")).execute(&server).await.unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(admin_url).unwrap().database(DB);
    let admin = PgPoolOptions::new().max_connections(4).connect_with(options.clone()).await.unwrap();
    for sql in [
        "CREATE SCHEMA nano_shared".to_owned(),
        TABLE.to_owned(),
        GEN1_ONLY_COMPOSITE.to_owned(),
        "CREATE TRIGGER trg_detection_lake_composite_ack BEFORE INSERT OR UPDATE ON detection_finding_lake_outbox \
         FOR EACH ROW EXECUTE FUNCTION enforce_detection_lake_composite_ack()".to_owned(),
        format!("CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE session_user WHEN '{ROLE}' THEN '{A}'::uuid END $$"),
        format!("CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user = '{ROLE}' THEN 'finding_drain' END $$"),
        format!("GRANT USAGE ON SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT SELECT, UPDATE, DELETE ON detection_finding_lake_outbox TO {ROLE}"),
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY".to_owned(),
        // Enterprise shape: restrictive tenant scope + capability verbs (9007000, 9012800).
        "CREATE POLICY scope ON detection_finding_lake_outbox AS RESTRICTIVE FOR ALL USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_select ON detection_finding_lake_outbox FOR SELECT USING (nano_shared.lake_data_path_capability() = 'finding_drain')".to_owned(),
        "CREATE POLICY drain_update ON detection_finding_lake_outbox FOR UPDATE USING (nano_shared.lake_data_path_capability() = 'finding_drain') WITH CHECK (nano_shared.lake_data_path_capability() = 'finding_drain')".to_owned(),
        "CREATE POLICY drain_delete ON detection_finding_lake_outbox FOR DELETE USING (nano_shared.lake_data_path_capability() = 'finding_drain' AND risk_published_at IS NOT NULL AND event_published_at IS NOT NULL AND published_at < NOW() - INTERVAL '8 days')".to_owned(),
    ] {
        sqlx::query(&sql).execute(&admin).await.unwrap();
    }
    let drain = PgPoolOptions::new().max_connections(1).connect_with(options.username(ROLE)).await.unwrap();
    (server, admin, drain)
}

fn finding(tenant: &str, id: &str, time_us: i64) -> (serde_json::Value, serde_json::Value) {
    let compact = serde_json::json!({
        "id":id, "timestamp_us":time_us, "entity":"user1@example.com", "stamped_entity_type":"email",
        "risk_score":40, "rule_id":"rule-1", "rule_name":"fixture", "severity":"medium",
        "origin_source_types":["auth"], "mitre_tactics":[]
    });
    let event = serde_json::json!({
        "class_uid":2004, "time":time_us / 1000,
        "metadata":{"uid":id,"tenant_uid":tenant,"log_source":"detections"},
        "message": format!("rule matched {id}"),
        "unmapped":{"signal_type":"alert","alert_id":format!("alert-{id}")}
    });
    (compact, event)
}

/// `acked`: `None` = pending; `Some((snapshot, published_days_ago))`.
async fn insert(admin: &sqlx::PgPool, tenant: &str, id: &str, acked: Option<(&str, Option<i32>)>) {
    let (compact, event) = finding(tenant, id, chrono::Utc::now().timestamp_micros());
    let (snapshot, days) = acked.map_or((None, None), |(snapshot, days)| (Some(snapshot), days));
    sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, compact_finding, ocsf_event, \
        risk_published_at, risk_snapshot_id, event_published_at, event_snapshot_id, published_at) \
        VALUES ($1,$2,$3,$4,$5, CASE WHEN $6::text IS NULL THEN NULL ELSE now() END, $6, CASE WHEN $6::text IS NULL THEN NULL ELSE now() END, $6, \
        CASE WHEN $7::int IS NULL THEN NULL ELSE now() - make_interval(days => $7) END)")
        .bind(uuid::Uuid::parse_str(tenant).unwrap()).bind(tenant).bind(id).bind(&compact).bind(&event)
        .bind(snapshot).bind(days)
        .execute(admin).await.unwrap();
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    risk_published_at: Option<chrono::DateTime<chrono::Utc>>,
    event_snapshot_id: Option<String>,
    risk_snapshot_id: Option<String>,
    published_at: Option<chrono::DateTime<chrono::Utc>>,
    published_snapshot_id: Option<String>,
    publish_attempts: i32,
    last_error: Option<String>,
}

async fn row(admin: &sqlx::PgPool, tenant: &str, id: &str) -> Option<Row> {
    sqlx::query_as("SELECT risk_published_at, event_snapshot_id, risk_snapshot_id, published_at, published_snapshot_id, \
        publish_attempts, last_error FROM detection_finding_lake_outbox WHERE tenant_id = $1 AND finding_id = $2")
        .bind(tenant).bind(id).fetch_optional(admin).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lean_drain_retries_completes_and_prunes_findings() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "this test requires a loopback disposable risktest server");
    let (server, admin, drain) = setup(&admin_url).await;

    // 344 backfill: a lean row acknowledged under the gen1-only trigger is
    // stamped with its acknowledgement time; a gen1 component ack is not.
    insert(&admin, A, "acked-before-344", Some(("parts:7:aa", None))).await;
    insert(&admin, A, "gen1-event-only", None).await;
    sqlx::query("UPDATE detection_finding_lake_outbox SET event_published_at = now(), event_snapshot_id = 'iceberg-1', \
        risk_published_at = now(), risk_snapshot_id = 'risk-1' WHERE finding_id = 'gen1-event-only'")
        .execute(&admin).await.unwrap();
    assert!(row(&admin, A, "acked-before-344").await.unwrap().published_at.is_none(), "pre-344 trigger leaves lean acks unstamped");
    sqlx::raw_sql(MIGRATION_346).execute(&admin).await.unwrap();
    let backfilled = row(&admin, A, "acked-before-344").await.unwrap();
    assert_eq!(backfilled.published_at, backfilled.risk_published_at, "backfill stamps the acknowledgement time");
    assert!(row(&admin, A, "gen1-event-only").await.unwrap().published_at.is_none(),
        "gen1 risk+event without a serving generation stays incomplete");
    sqlx::raw_sql(MIGRATION_346).execute(&admin).await.unwrap(); // idempotent

    let dir = tempfile::tempdir().unwrap();
    let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
    let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-retry", SigningKey::from_bytes(&[9; 32])).unwrap()));
    let trusted = signer.trusted();
    let queue: &'static SpoolQueue = Box::leak(Box::new(SpoolQueue::new(dir.path().join("spool"), A).unwrap()));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let ingestor = Ingestor::open(IngestConfig::new(A, dir.path().join("ingest")), store, store, queue, signer, trusted.clone(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    let context = ingestor.finding_context();
    let ingestor: &'static tokio::sync::Mutex<Ingestor<'static>> = Box::leak(Box::new(tokio::sync::Mutex::new(ingestor)));
    let transport = GateAppend { gate: FindingGate::new(FindingGateConfig::default()), ingestor, context };

    // Attempted but unpublished: the pass claims the row, writes its receipt,
    // and the append is refused. The row stays pending with the attempt and
    // error recorded, and its claim ends with the pass.
    insert(&admin, A, "retry-me", None).await;
    let refusing = RefusingTransport(AtomicU32::new(0));
    let failed = drain_pass(&drain, store, signer, &trusted, A, 1, &refusing, &dir.path().join("w0"), now_ms).await;
    assert!(failed.is_err());
    assert_eq!(refusing.0.load(Ordering::Relaxed), 1);
    let attempted = row(&admin, A, "retry-me").await.unwrap();
    assert!(attempted.risk_published_at.is_none() && attempted.published_at.is_none());
    assert_eq!(attempted.publish_attempts, 1);
    assert!(attempted.last_error.as_deref().is_some_and(|e| e.contains("injected owner refusal")), "{attempted:?}");
    let mut probe = admin.begin().await.unwrap();
    let _: String = sqlx::query_scalar("SELECT finding_id FROM detection_finding_lake_outbox WHERE finding_id = 'retry-me' FOR UPDATE NOWAIT")
        .fetch_one(&mut *probe).await.expect("a failed pass must release its claim");
    probe.rollback().await.unwrap();

    // The retry publishes the row from its pre-existing receipt and
    // completes it: both components at one part-log head, published_at set.
    let pass = drain_pass(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join("w1"),
        chrono::Utc::now().timestamp_millis()).await.unwrap();
    assert_eq!((pass.seen, pass.preexisting_receipts, pass.published, pass.committed), (1, 1, 1, 1), "{pass:?}");
    let done = row(&admin, A, "retry-me").await.unwrap();
    let marker = done.event_snapshot_id.clone().unwrap();
    assert!(marker.starts_with("parts:"), "{done:?}");
    assert_eq!(done.risk_snapshot_id.as_deref(), Some(marker.as_str()));
    assert!(done.published_at.is_some(), "a lean ack is a complete delivery: {done:?}");
    assert_eq!(done.published_snapshot_id.as_deref(), Some(marker.as_str()));
    assert_eq!((done.publish_attempts, done.last_error.as_deref()), (2, None));

    // A further pass is idle: nothing is re-published.
    let idle = drain_pass(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join("w2"),
        chrono::Utc::now().timestamp_millis()).await.unwrap();
    assert_eq!((idle.backlog, idle.seen, idle.committed), (0, 0, 0), "{idle:?}");

    // Retention: only this tenant's delivered rows past 8 days go.
    insert(&admin, A, "old-delivered", Some(("parts:1:bb", Some(9)))).await;
    insert(&admin, A, "recent-delivered", Some(("parts:2:cc", Some(1)))).await;
    insert(&admin, B, "other-tenant-old", Some(("parts:3:dd", Some(9)))).await;
    sqlx::query("UPDATE detection_finding_lake_outbox SET created_at = now() - interval '10 days' WHERE finding_id = 'gen1-event-only'")
        .execute(&admin).await.unwrap();
    let mut cache = DrainLogCache::default();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let first = drain_pass_cached(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join("w3"), now_ms,
        &|_, _| {}, &mut cache).await.unwrap();
    assert_eq!(first.pruned, 1, "{first:?}");
    assert!(row(&admin, A, "old-delivered").await.is_none());
    for (tenant, id) in [(A, "recent-delivered"), (B, "other-tenant-old"), (A, "retry-me"), (A, "acked-before-344")] {
        assert!(row(&admin, tenant, id).await.is_some(), "{id} must be kept");
    }
    // The gen1 row without a serving generation (no published_at) is kept
    // too, and the drain cannot delete what the policy has not released.
    assert!(row(&admin, A, "gen1-event-only").await.is_some());
    let forced = sqlx::query("DELETE FROM detection_finding_lake_outbox WHERE finding_id IN ('recent-delivered','other-tenant-old','gen1-event-only')")
        .execute(&drain).await.unwrap();
    assert_eq!(forced.rows_affected(), 0, "RLS keeps recent, foreign and incomplete rows out of the drain's reach");
    // A long-running loop prunes on a schedule, not every 1 s pass.
    insert(&admin, A, "old-delivered-2", Some(("parts:4:ee", Some(9)))).await;
    let soon = drain_pass_cached(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join("w4"), now_ms + 1_000,
        &|_, _| {}, &mut cache).await.unwrap();
    assert_eq!(soon.pruned, 0);
    let later = drain_pass_cached(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join("w5"),
        now_ms + nanosiem_lake_worker::part_ingest::finding_outbox::OUTBOX_PRUNE_EVERY_MS, &|_, _| {}, &mut cache).await.unwrap();
    assert_eq!(later.pruned, 1);

    drop(drain);
    drop(admin);
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
    sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}")).execute(&server).await.unwrap();
}
