// SPDX-License-Identifier: AGPL-3.0-or-later

//! The stuck finding drain (a lean test tenant, 2026-09-29): 103 outbox
//! rows never drained. Earlier passes had created receipt objects and then
//! failed (missing ingest R2 grant, expired owner-sign bearer), and the
//! assignment moved to a new cell and writer epoch. Every later pass treated
//! those receipts as crash replay and scanned the part log from genesis, one
//! GET at a time (~10/s, ~50 min for 30k entries) while holding the outbox
//! rows locked, logging nothing, until the process was replaced.
//!
//! Run against a disposable PostgreSQL server with NANO_RISK_TEST_PG set to
//! its loopback administrator URL (`postgres://postgres@127.0.0.1:<port>/risktest`).
//! This test creates and drops its own `risktest_stuck_drain` database.

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_outbox::{committed_receipts, drain_pass, FindingReceipt};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, ObjectStore, SourceRef, WriteHints};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

const A: &str = "00000000-0000-4000-8000-00000000000a";
const DB: &str = "risktest_stuck_drain";
const ROLE: &str = "stuck_drain_a";

/// Counts part-log entry GETs: the genesis scan's signature.
struct CountingStore<'a> {
    inner: &'a LocalObjectStore,
    entry_gets: AtomicUsize,
}

impl CountingStore<'_> {
    fn take(&self) -> usize {
        self.entry_gets.swap(0, Ordering::SeqCst)
    }
}

#[async_trait]
impl ObjectStore for CountingStore<'_> {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        if key.contains("/log/entries/") {
            self.entry_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.inner.put_if_absent_with(key, bytes, hints).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

struct FixtureAppend<'a> {
    ingest: tokio::sync::Mutex<Ingestor<'a>>,
    now_ms: i64,
}

#[async_trait]
impl FindingAppendTransport for FixtureAppend<'_> {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        self.ingest.lock().await.append_finding(FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch,
            schema: request.schema.clone(), parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
        }, self.now_ms).await
    }
}

async fn open_ingest<'a>(dir: &Path, store: &'a LocalObjectStore, queue: &'a SpoolQueue,
    signer: &'a LocalPartSigner, epoch: u64, now_ms: i64) -> FixtureAppend<'a> {
    let mut cfg = IngestConfig::new(A, dir.join(format!("ingest-epoch-{epoch}")));
    cfg.writer_epoch = epoch;
    let ingest = Ingestor::open(cfg, store, store, queue, signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    FixtureAppend { ingest: tokio::sync::Mutex::new(ingest), now_ms }
}

fn finding(id: &str, time_us: i64) -> (serde_json::Value, serde_json::Value) {
    let compact = serde_json::json!({
        "id":id, "timestamp_us":time_us, "entity":"alice@example.com",
        "stamped_entity_type":"email", "risk_score":40, "rule_id":"rule-1",
        "rule_name":"fixture", "severity":"medium", "origin_source_types":["auth"], "mitre_tactics":[]
    });
    let event = serde_json::json!({
        "class_uid":2004, "time":time_us / 1000,
        "metadata":{"uid":id,"tenant_uid":A,"log_source":"detections"},
        "unmapped":{"signal_type":"alert","alert_id":format!("alert-{id}")}
    });
    (compact, event)
}

async fn insert(admin: &sqlx::PgPool, id: &str, time_us: i64, age: &str) -> SourceRef {
    let (compact, event) = finding(id, time_us);
    sqlx::query(&format!("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, \
        compact_finding, ocsf_event, created_at) VALUES ($1,$2,$3,$4,$5, now() - interval '{age}')"))
        .bind(uuid::Uuid::parse_str(A).unwrap()).bind(A).bind(id)
        .bind(&compact).bind(&event).execute(admin).await.unwrap();
    FindingReceipt::new(A, id, &compact, &event).unwrap().source().unwrap()
}

/// What a failed earlier pass leaves behind: the receipt object only.
async fn leave_receipt(store: &LocalObjectStore, id: &str, time_us: i64) -> SourceRef {
    let (compact, event) = finding(id, time_us);
    let receipt = FindingReceipt::new(A, id, &compact, &event).unwrap();
    let source = receipt.source().unwrap();
    assert!(store.put_if_absent(&source.key, &receipt.bytes().unwrap()).await.unwrap());
    source
}

/// What ingest leaves when it crashes between durable intent and `Add`.
async fn leave_attempt_marker(store: &LocalObjectStore, source: &SourceRef) {
    let key = format!("lake/parts/v1/tenant={A}/finding-outbox/receipts/.ingest-attempts/{}.json",
        hex::encode(Sha256::digest(source.key.as_bytes())));
    assert!(store.put_if_absent(&key, &serde_json::to_vec(source).unwrap()).await.unwrap());
}

async fn setup(admin_url: &str) -> (sqlx::PgPool, sqlx::PgPool, sqlx::PgPool) {
    let server = PgPoolOptions::new().max_connections(1).connect(admin_url).await.unwrap();
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
    sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE ROLE {ROLE} LOGIN")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {DB}")).execute(&server).await.unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(admin_url).unwrap().database(DB);
    let admin = PgPoolOptions::new().max_connections(2).connect_with(options.clone()).await.unwrap();
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

#[tokio::test]
async fn receipts_from_failed_attempts_under_an_old_epoch_drain_without_a_genesis_scan() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "stuck drain test requires a loopback disposable risktest server");
    let (server, admin, drain) = setup(&admin_url).await;
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
    let counting = CountingStore { inner: &store, entry_gets: AtomicUsize::new(0) };
    let signer = LocalPartSigner::new("lab-stuck-drain", SigningKey::from_bytes(&[9; 32])).unwrap();
    let trusted = signer.trusted();
    let queue = SpoolQueue::new(dir.path().join("spool"), A).unwrap();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let time_us = (now_ms - 3_600_000) * 1_000;

    // The old cell (writer epoch 2) opened the log; the detect pass under it
    // wrote receipts for f1/f2 and then failed before any append.
    drop(open_ingest(dir.path(), &store, &queue, &signer, 2, now_ms).await);
    let f1 = insert(&admin, "f1", time_us, "20 hours").await;
    let f2 = insert(&admin, "f2", time_us + 1, "19 hours").await;
    let f3 = insert(&admin, "f3", time_us + 2, "1 minute").await;
    assert_eq!(leave_receipt(&store, "f1", time_us).await, f1);
    assert_eq!(leave_receipt(&store, "f2", time_us + 1).await, f2);

    // The assignment moved: the new cell's ingest runs writer epoch 3.
    let append = open_ingest(dir.path(), &store, &queue, &signer, 3, now_ms + 1).await;
    // A drain still bound to the old epoch is fenced and loses nothing.
    assert!(drain_pass(&drain, &counting, &signer, &trusted, A, 2, &append, &dir.path().join("w-old"), now_ms + 2)
        .await.is_err(), "the old writer epoch must be fenced by the new ingest");
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_finding_lake_outbox WHERE event_published_at IS NULL")
        .fetch_one(&admin).await.unwrap();
    assert_eq!(pending, 3, "a fenced pass must leave every row in the outbox");
    counting.take();

    // The stuck state: pre-existing receipts, no ingest attempt markers.
    // The current-epoch pass republishes them without reading the log.
    let pass = drain_pass(&drain, &counting, &signer, &trusted, A, 3, &append, &dir.path().join("w1"), now_ms + 3)
        .await.unwrap();
    // Publishing reads only the log tail since the last checkpoint
    // (`load_log`); the genesis scan fetches a whole window (32) at least.
    let gets = counting.take();
    assert!(gets <= 4, "receipts ingest never attempted must not trigger a part-log scan ({gets} entry GETs)");
    // The fenced epoch-2 pass above also left f3's receipt: all three exist.
    assert_eq!((pass.backlog, pass.seen, pass.preexisting_receipts, pass.replay_checked), (3, 3, 3, 0));
    assert_eq!((pass.published, pass.replayed, pass.committed, pass.skipped), (3, 0, 3, None));
    assert!(pass.oldest_age_ms(now_ms) >= 20 * 3_600_000 - 60_000, "oldest row age is reported");

    // A genuine crash window (ingest wrote its intent marker, no Add) still
    // gets the log proof, then republishes exactly once.
    let f4 = insert(&admin, "f4", time_us + 3, "2 minutes").await;
    assert_eq!(leave_receipt(&store, "f4", time_us + 3).await, f4);
    leave_attempt_marker(&store, &f4).await;
    let pass = drain_pass(&drain, &counting, &signer, &trusted, A, 3, &append, &dir.path().join("w2"), now_ms + 4)
        .await.unwrap();
    let gets = counting.take();
    assert!(gets >= 32, "an attempted receipt is proven against the whole log ({gets} entry GETs)");
    assert_eq!((pass.backlog, pass.preexisting_receipts, pass.replay_checked, pass.published, pass.committed), (1, 1, 1, 1, 1));

    // Rows locked by another session are reported, not silently skipped.
    let _f5 = insert(&admin, "f5", time_us + 4, "30 seconds").await;
    let mut holder = admin.begin().await.unwrap();
    sqlx::query("SELECT finding_id FROM detection_finding_lake_outbox WHERE finding_id = 'f5' FOR UPDATE")
        .fetch_all(&mut *holder).await.unwrap();
    let pass = drain_pass(&drain, &counting, &signer, &trusted, A, 3, &append, &dir.path().join("w3"), now_ms + 5)
        .await.unwrap();
    assert_eq!((pass.backlog, pass.seen, pass.committed), (1, 0, 0));
    assert!(pass.skipped.is_some(), "a locked backlog names its skip reason");
    holder.rollback().await.unwrap();
    let pass = drain_pass(&drain, &counting, &signer, &trusted, A, 3, &append, &dir.path().join("w4"), now_ms + 6)
        .await.unwrap();
    assert_eq!((pass.backlog, pass.published, pass.committed), (1, 1, 1));
    let pass = drain_pass(&drain, &counting, &signer, &trusted, A, 3, &append, &dir.path().join("w5"), now_ms + 7)
        .await.unwrap();
    assert_eq!((pass.backlog, pass.seen, pass.committed, pass.oldest_created_ms), (0, 0, 0, None));

    // Nothing lost, nothing doubled: every row acked with a log position and
    // every receipt consumed by exactly one signed Add.
    let acked: Vec<(String, String)> = sqlx::query_as(
        "SELECT finding_id, event_snapshot_id FROM detection_finding_lake_outbox ORDER BY finding_id")
        .fetch_all(&admin).await.unwrap();
    assert_eq!(acked.len(), 5);
    assert!(acked.iter().all(|(_, head)| head.starts_with("parts:")));
    let mut sources = vec![f1, f2, f3, f4];
    let (c5, e5) = finding("f5", time_us + 4);
    sources.push(FindingReceipt::new(A, "f5", &c5, &e5).unwrap().source().unwrap());
    let committed = committed_receipts(&store, A, &sources, &trusted).await.unwrap();
    assert_eq!(committed.len(), 5, "each receipt is committed exactly once");

    drop(drain);
    drop(admin);
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
}
