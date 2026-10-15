// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3067 (a lean test tenant, 2026-09-30): after an ingest restart the
//! finding drain moved 128 findings per 80-150 s pass. Every receipt,
//! marker and log-entry round trip was serial, and appends waited behind a
//! whole ingest tick (prevalence rebuild, catch-up flush, merges). The
//! backlog grew past 2,000 while 17 alerting rules produced faster.
//!
//! Here, at 10x the live finding rate, against an object store with R2-like
//! latency and an ingest loop that keeps taking the ingestor lock, the drain
//! must keep the backlog bounded and the oldest finding under 60 s. Also: an
//! append whose requester's deadline has passed is refused, not committed.
//!
//! Run against a disposable PostgreSQL server with NANO_RISK_TEST_PG set to
//! its loopback administrator URL (`postgres://postgres@127.0.0.1:<port>/risktest`).

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_gate::{FindingGate, FindingGateConfig};
use nanosiem_lake_worker::part_ingest::finding_outbox::drain_pass;
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, FindingAppendContext, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, ObjectStore, WriteHints};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sqlx::postgres::PgPoolOptions;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const A: &str = "00000000-0000-4000-8000-00000000003a";
const DB: &str = "risktest_drain_throughput";
const ROLE: &str = "drain_throughput_a";
/// R2-like round trip per object-store call.
const LATENCY: Duration = Duration::from_millis(25);

struct SlowStore {
    inner: LocalObjectStore,
    calls: AtomicU64,
}

impl SlowStore {
    async fn wait(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(LATENCY).await;
    }
}

#[async_trait]
impl ObjectStore for SlowStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.wait().await;
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.wait().await;
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.wait().await;
        self.inner.put_if_absent_with(key, bytes, hints).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.wait().await;
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.wait().await;
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.wait().await;
        self.inner.list(prefix).await
    }
}

/// The cell's path: the finding gate, the shared ingestor lock.
struct GateAppend {
    store: &'static SlowStore,
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
        "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, PRIMARY KEY (security_tenant_id, tenant_id, finding_id))".to_owned(),
        format!("CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE session_user WHEN '{ROLE}' THEN '{A}'::uuid END $$"),
        format!("CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user = '{ROLE}' THEN 'finding_drain' END $$"),
        format!("GRANT USAGE ON SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT SELECT, UPDATE ON detection_finding_lake_outbox TO {ROLE}"),
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY".to_owned(),
        "CREATE POLICY drain_select ON detection_finding_lake_outbox FOR SELECT USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_update ON detection_finding_lake_outbox FOR UPDATE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
    ] {
        sqlx::query(&sql).execute(&admin).await.unwrap();
    }
    let drain = PgPoolOptions::new().max_connections(1).connect_with(options.username(ROLE)).await.unwrap();
    (server, admin, drain)
}

async fn insert(admin: &sqlx::PgPool, id: &str, time_us: i64) {
    let compact = serde_json::json!({
        "id":id, "timestamp_us":time_us, "entity":format!("user{}@example.com", time_us % 97),
        "stamped_entity_type":"email", "risk_score":40, "rule_id":"rule-1",
        "rule_name":"fixture", "severity":"medium", "origin_source_types":["auth"], "mitre_tactics":[]
    });
    let event = serde_json::json!({
        "class_uid":2004, "time":time_us / 1000,
        "metadata":{"uid":id,"tenant_uid":A,"log_source":"detections"},
        "message": format!("whole-tenant alerting rule matched {id} {}", "x".repeat(1_500)),
        "unmapped":{"signal_type":"alert","alert_id":format!("alert-{id}")}
    });
    sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, compact_finding, ocsf_event) VALUES ($1,$2,$3,$4,$5)")
        .bind(uuid::Uuid::parse_str(A).unwrap()).bind(A).bind(id).bind(&compact).bind(&event)
        .execute(admin).await.unwrap();
}

async fn backlog(admin: &sqlx::PgPool) -> (i64, f64) {
    sqlx::query_as("SELECT count(*), COALESCE(EXTRACT(EPOCH FROM now() - min(created_at))::float8, 0) \
        FROM detection_finding_lake_outbox WHERE event_published_at IS NULL OR risk_published_at IS NULL")
        .fetch_one(admin).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_keeps_up_at_ten_times_the_live_rate_beside_a_busy_ingest_loop() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "throughput test requires a loopback disposable risktest server");
    let (server, admin, drain) = setup(&admin_url).await;
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let store: &'static SlowStore = Box::leak(Box::new(SlowStore {
        inner: LocalObjectStore::new(dir.path().join("store")).unwrap(), calls: AtomicU64::new(0) }));
    let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-throughput", SigningKey::from_bytes(&[5; 32])).unwrap()));
    let trusted = signer.trusted();
    let queue: &'static SpoolQueue = Box::leak(Box::new(SpoolQueue::new(dir.path().join("spool"), A).unwrap()));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let cfg = IngestConfig::new(A, dir.path().join("ingest"));
    let ingestor = Ingestor::open(cfg, store, store, queue, signer, trusted.clone(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    let context = ingestor.finding_context();
    let ingestor: &'static tokio::sync::Mutex<Ingestor<'static>> = Box::leak(Box::new(tokio::sync::Mutex::new(ingestor)));
    let transport = GateAppend { store, gate: FindingGate::new(FindingGateConfig::default()), ingestor, context };

    // A stale append (its requester stopped waiting) is refused, never
    // committed: its ack would be lost and the next pass would have to
    // prove the replay against the log.
    insert(&admin, "stale", (now_ms - 60_000) * 1_000).await;
    let stale = StaleTransport(&transport);
    assert!(drain_pass(&drain, store, signer, &trusted, A, 1, &stale, &dir.path().join("w-stale"), now_ms).await.is_err());

    // The ingest loop: phases that each hold the lock ~1.5 s, back to back
    // with a short gap (a prevalence rebuild step, a catch-up flush).
    let stop = Arc::new(AtomicBool::new(false));
    let busy = {
        let stop = stop.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let _held = ingestor.lock().await;
                tokio::time::sleep(Duration::from_millis(1_500)).await;
                drop(_held);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    // 10x the live rate: live ~2 findings/s from 17 whole-tenant rules.
    let producer = {
        let (admin, stop) = (admin.clone(), stop.clone());
        tokio::spawn(async move {
            let mut n = 0_u64;
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_secs(40) && !stop.load(Ordering::Relaxed) {
                for _ in 0..20 {
                    n += 1;
                    insert(&admin, &format!("f{n:06}"), chrono::Utc::now().timestamp_micros()).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            n
        })
    };
    let started = std::time::Instant::now();
    let mut worst_age = 0.0_f64;
    let mut worst_backlog = 0_i64;
    let mut passes = 0;
    loop {
        let pass = drain_pass(&drain, store, signer, &trusted, A, 1, &transport, &dir.path().join(format!("w{passes}")),
            chrono::Utc::now().timestamp_millis()).await.unwrap();
        passes += 1;
        let (count, age) = backlog(&admin).await;
        worst_age = worst_age.max(age);
        worst_backlog = worst_backlog.max(count);
        if producer.is_finished() && count == 0 {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(120), "the drain did not catch up ({count} left)");
        if pass.seen == 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    stop.store(true, Ordering::Relaxed);
    busy.await.unwrap();
    let produced = producer.await.unwrap();
    println!("{produced} findings at 20/s: {passes} passes, worst backlog {worst_backlog}, worst oldest age {worst_age:.1} s, {} store calls, {:.1} s",
        store.calls.load(Ordering::Relaxed), started.elapsed().as_secs_f64());
    // Contract: under 60 s. Measured 9 s and 40 rows; serial round trips
    // with 128-row batches measured 47.7 s and 372 rows here (and far worse
    // at live R2 latency), so the bound keeps a regression visible.
    assert!(worst_age < 30.0, "the oldest finding waited {worst_age:.1} s");
    assert!(worst_backlog < 200, "the backlog grew to {worst_backlog}");

    drop(drain);
    drop(admin);
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
}

/// A requester whose deadline already passed when ingest got the request.
struct StaleTransport<'a>(&'a GateAppend);

#[async_trait]
impl FindingAppendTransport for StaleTransport<'_> {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        let stale = FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
            parts: request.parts.clone(), receipts: request.receipts.clone(),
            deadline_unix_ms: Some(chrono::Utc::now().timestamp_millis() - 1),
        };
        let before = nanosiem_lake_worker::parts::part_log::load_log(&self.0.store.inner, A).await?.head().map(|h| h.0);
        let result = self.0.submit(&stale).await;
        let after = nanosiem_lake_worker::parts::part_log::load_log(&self.0.store.inner, A).await?.head().map(|h| h.0);
        assert_eq!(before, after, "a stale append must not reach the log");
        result
    }
}
