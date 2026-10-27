// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4656: the ops finding-replay livelock (hosted, 2026-10-26). A
//! finding append was cut by the T92 control roll; the cell roll then
//! restarted detect and ingest. Every drain pass and every ingest retry
//! re-read the whole 57.8k-entry part log from seq 0 (~11 min each, longer
//! than ingest's append deadline): ~474k R2 GETs/h, and 0 of ~20 queued
//! findings delivered.
//!
//! The production drain (`drain_pass`, a tenant-bound RLS principal), the
//! production ingest gate (`FindingGate`) and `Ingestor::open`, over a log
//! of [`HISTORY`] entries. Both ways a roll cuts an append (before the `Add`
//! lands, and after it lands with the acknowledgement lost), then a restart
//! of BOTH roles. Each pass reads O(new entries) of the log (at most the
//! checkpoint tail the drain's own log view needs), and every finding is
//! delivered exactly once.
//!
//! Run against a disposable PostgreSQL server with NANO_RISK_TEST_PG set to
//! its loopback administrator URL (`postgres://postgres@127.0.0.1:<port>/risktest`).

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_gate::{FindingGate, FindingGateConfig};
use nanosiem_lake_worker::part_ingest::finding_outbox::{drain_pass, FindingReceipt};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, FindingAppendContext, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::format::LogKeys;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, LogEntry, LogOp, LogSchema, ObjectStore, PartLogWriter, SourceRef, WriteHints};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sqlx::postgres::PgPoolOptions;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const A: &str = "00000000-0000-4000-8000-000000004656";
const DB: &str = "risktest_finding_replay_floor";
const ROLE: &str = "finding_replay_floor_a";
/// Entries already in the log (ops had 57.8k).
const HISTORY: u64 = 5_000;
/// What one pass may read: the drain view's checkpoint tail (load_log,
/// at most CHECKPOINT_EVERY = 1,024 entries) plus a few fetch windows.
const PASS_READ_BOUND: usize = 1_024 + 6 * 32;

/// Counts part-log entry GETs; cuts the next finding `Add` entry PUT before
/// it lands or after it lands (acknowledgement lost).
struct RollStore {
    inner: LocalObjectStore,
    entry_gets: AtomicUsize,
    cut_before: AtomicBool,
    cut_after: AtomicBool,
}

impl RollStore {
    fn take(&self) -> usize {
        self.entry_gets.swap(0, Ordering::SeqCst)
    }

    fn cut(&self, key: &str, bytes: &[u8], flag: &AtomicBool) -> anyhow::Result<()> {
        let add = key.contains("/log/entries/") && bytes.windows(12).any(|window| window == br#""kind":"add""#);
        if add && flag.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected: the cell was rolled during the append");
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for RollStore {
    async fn modified_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
        self.inner.modified_ms(key).await
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        if key.contains("/log/entries/") {
            self.entry_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.cut(key, bytes, &self.cut_before)?;
        let created = self.inner.put_if_absent(key, bytes).await?;
        self.cut(key, bytes, &self.cut_after)?;
        Ok(created)
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.cut(key, bytes, &self.cut_before)?;
        let created = self.inner.put_if_absent_with(key, bytes, hints).await?;
        self.cut(key, bytes, &self.cut_after)?;
        Ok(created)
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

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// The cell's ingest role: the production gate over the production ingestor.
struct IngestRole {
    gate: FindingGate,
    ingestor: &'static tokio::sync::Mutex<Ingestor<'static>>,
    context: FindingAppendContext<'static>,
    submits: AtomicUsize,
}

#[async_trait]
impl FindingAppendTransport for IngestRole {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        let request = FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
            parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
        };
        let admitted = self.gate.admit()?;
        self.gate.append(admitted, self.ingestor, &self.context, request, || chrono::Utc::now().timestamp_millis()).await
    }
}

async fn start_ingest(dir: &std::path::Path, store: &'static RollStore, queue: &'static SpoolQueue,
    signer: &'static LocalPartSigner, name: &str) -> IngestRole {
    let mut cfg = IngestConfig::new(A, dir.join(name));
    cfg.writer_epoch = 1;
    let ingestor = Ingestor::open(cfg, store, &store.inner, queue, signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    let context = ingestor.finding_context();
    IngestRole {
        // Production defaults (40 s deadline): the proof must fit inside it.
        gate: FindingGate::new(FindingGateConfig::default()),
        ingestor: leak(tokio::sync::Mutex::new(ingestor)),
        context,
        submits: AtomicUsize::new(0),
    }
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

async fn insert(admin: &sqlx::PgPool, id: &str, time_us: i64) -> SourceRef {
    let (compact, event) = finding(id, time_us);
    sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, \
        compact_finding, ocsf_event) VALUES ($1,$2,$3,$4,$5)")
        .bind(uuid::Uuid::parse_str(A).unwrap()).bind(A).bind(id)
        .bind(&compact).bind(&event).execute(admin).await.unwrap();
    FindingReceipt::new(A, id, &compact, &event).unwrap().source().unwrap()
}

/// Ground truth from genesis, no floors: the seqs whose `Add` consumed it.
async fn consumptions(store: &LocalObjectStore, source: &SourceRef) -> Vec<u64> {
    let keys = LogKeys::new(A).unwrap();
    let mut seqs = Vec::new();
    for seq in 0.. {
        let Some(bytes) = store.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, A).unwrap().op {
            if consumed.iter().any(|item| item == source) {
                seqs.push(seq);
            }
        }
    }
    seqs
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
        "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, published_at timestamptz, PRIMARY KEY (security_tenant_id, tenant_id, finding_id))".to_owned(),
        format!("CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE session_user WHEN '{ROLE}' THEN '{A}'::uuid END $$"),
        format!("CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user = '{ROLE}' THEN 'finding_drain' END $$"),
        format!("GRANT USAGE ON SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT SELECT, UPDATE, DELETE ON detection_finding_lake_outbox TO {ROLE}"),
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY".to_owned(),
        "CREATE POLICY drain_select ON detection_finding_lake_outbox FOR SELECT USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_update ON detection_finding_lake_outbox FOR UPDATE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_delete ON detection_finding_lake_outbox FOR DELETE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
    ] {
        sqlx::query(&sql).execute(&admin).await.unwrap();
    }
    let drain = PgPoolOptions::new().max_connections(1).connect_with(options.username(ROLE)).await.unwrap();
    (server, admin, drain)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_append_after_a_restart_of_both_roles_delivers_every_finding_once_with_bounded_reads() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "replay floor test requires a loopback disposable risktest server");
    let (server, admin, drain) = setup(&admin_url).await;
    let dir = tempfile::tempdir().unwrap();
    let store = leak(RollStore {
        inner: LocalObjectStore::new(dir.path().join("store")).unwrap(),
        entry_gets: AtomicUsize::new(0),
        cut_before: AtomicBool::new(false),
        cut_after: AtomicBool::new(false),
    });
    let signer = leak(LocalPartSigner::new("lab-replay-floor", SigningKey::from_bytes(&[46; 32])).unwrap());
    let trusted = signer.trusted();
    let queue = leak(SpoolQueue::new(dir.path().join("spool"), A).unwrap());
    let now_ms = chrono::Utc::now().timestamp_millis();
    let time_us = (now_ms - 3_600_000) * 1_000;
    {
        let mut log = PartLogWriter::open(&store.inner, A, 1, &seed_schema(), now_ms).await.unwrap();
        let schema = LogSchema::from_arrow(&seed_schema()).unwrap();
        for _ in 1..HISTORY {
            log.append(LogOp::Schema { schema: schema.clone() }, now_ms).await.unwrap();
        }
    }

    let mut all = Vec::new();
    let mut generation = 0;
    for (round, lost_ack) in [(0, true), (1, false)] {
        let ids = (0..3).map(|i| format!("r{round}-f{i}")).collect::<Vec<_>>();
        let mut sources = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            sources.push(insert(&admin, id, time_us + (round * 10 + i) as i64).await);
        }
        all.extend(sources.clone());

        // The roll cuts the append: the pass fails, the rows stay queued.
        generation += 1;
        let ingest = start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")).await;
        if lost_ack {
            store.cut_after.store(true, Ordering::SeqCst);
        } else {
            store.cut_before.store(true, Ordering::SeqCst);
        }
        let cut = drain_pass(&drain, store, signer, &trusted, A, 1, &ingest, &dir.path().join(format!("w{round}a")),
            chrono::Utc::now().timestamp_millis()).await;
        assert!(cut.is_err(), "round {round}: the roll cut the pass");
        assert!(!store.cut_after.load(Ordering::SeqCst) && !store.cut_before.load(Ordering::SeqCst));
        let landed = consumptions(&store.inner, &sources[0]).await.len();
        assert_eq!(landed, usize::from(lost_ack), "round {round}");
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_finding_lake_outbox WHERE event_published_at IS NULL")
            .fetch_one(&admin).await.unwrap();
        assert_eq!(pending, 3, "round {round}: nothing is acknowledged by a cut pass");

        // The cell roll: BOTH roles restart with nothing in memory (a new
        // ingestor and gate; drain_pass builds a fresh log view per call).
        drop(ingest);
        generation += 1;
        let ingest = start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")).await;
        store.take();
        let started = std::time::Instant::now();
        let pass = drain_pass(&drain, store, signer, &trusted, A, 1, &ingest, &dir.path().join(format!("w{round}b")),
            chrono::Utc::now().timestamp_millis()).await.expect("the first pass after the restart delivers");
        let gets = store.take();
        assert!(started.elapsed() < FindingGateConfig::default().deadline, "round {round}: one deadline");
        assert!(gets <= PASS_READ_BOUND, "round {round}: {gets} entry GETs on a {HISTORY}-entry log");
        assert_eq!((pass.seen, pass.preexisting_receipts, pass.replay_checked, pass.committed), (3, 3, 3, 3),
            "round {round}: {pass:?}");
        if lost_ack {
            assert_eq!((pass.replayed, pass.published), (3, 0), "round {round}: the landed Add is acknowledged, not re-sent");
            assert_eq!(ingest.submits.load(Ordering::SeqCst), 0, "round {round}: no second append");
        } else {
            assert_eq!((pass.replayed, pass.published), (0, 3), "round {round}: the cut findings are sent");
            assert_eq!(ingest.submits.load(Ordering::SeqCst), 1);
        }
        let idle = drain_pass(&drain, store, signer, &trusted, A, 1, &ingest, &dir.path().join(format!("w{round}c")),
            chrono::Utc::now().timestamp_millis()).await.unwrap();
        assert_eq!((idle.backlog, idle.committed), (0, 0), "round {round}");
        drop(ingest);
    }

    // Exactly once, from genesis: every queued finding acknowledged with the
    // one Add that consumed its receipt.
    let acked: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT finding_id, event_snapshot_id FROM detection_finding_lake_outbox ORDER BY finding_id")
        .fetch_all(&admin).await.unwrap();
    assert_eq!(acked.len(), 6);
    let keys = LogKeys::new(A).unwrap();
    for ((id, head), source) in acked.iter().zip(all.iter()) {
        let seqs = consumptions(&store.inner, source).await;
        assert_eq!(seqs.len(), 1, "{id} consumed at {seqs:?}");
        let sha = nanosiem_lake_worker::parts::sha256_hex(&store.inner.get(&keys.entry(seqs[0])).await.unwrap().unwrap());
        assert_eq!(head.as_deref(), Some(format!("parts:{}:{sha}", seqs[0]).as_str()), "{id}");
    }

    drop(drain);
    drop(admin);
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
}
