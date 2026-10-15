// SPDX-License-Identifier: AGPL-3.0-or-later

//! A slow or blocked finding append never stops part ingestion
//! (a lean test tenant, 2026-09-29).

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::discovery::SpoolQueue;
use crate::part_ingest::finding_outbox::FindingReceipt;
use crate::part_ingest::ingest::{finding_attempt_key, seed_schema, IngestConfig};
use crate::part_ingest::schema::{decode, infer_schema};
use crate::part_ingest::writer::{publish_parts, PartDraft, PartWriter, PartialSource};
use crate::part_ingest::SourceNotice;
use crate::part_query::risk::{finding_event, CompactFinding};
use crate::parts::levels::Level;
use crate::parts::part_log::{load_log, LocalObjectStore, LogSchema, ObjectStore, PartRef, WriteHints};
use crate::parts::provenance::{Admission, LocalPartSigner, PartInputs, PartSigner, SourceObject};
use crate::parts::{event_hour_of, DedupWindow};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

const TENANT: &str = "00000000-0000-4000-8000-0000000000fa";
/// 2026-09-26T18:00:00Z
const T0_US: i64 = 1_790_445_600_000_000;

/// A local store whose GETs of matching keys hang while `blocked`.
struct GatedStore {
    inner: LocalObjectStore,
    pattern: std::sync::Mutex<Option<String>>,
    open: tokio::sync::watch::Sender<bool>,
    blocked_gets: AtomicUsize,
}

impl GatedStore {
    fn block(&self, pattern: &str) {
        *self.pattern.lock().unwrap() = Some(pattern.to_owned());
        self.open.send_replace(false);
    }

    fn release(&self) {
        *self.pattern.lock().unwrap() = None;
        self.open.send_replace(true);
    }
}

#[async_trait]
impl ObjectStore for GatedStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let hit = self.pattern.lock().unwrap().as_deref().is_some_and(|p| key.contains(p) && !key.contains(".ingest-attempts"));
        if hit {
            self.blocked_gets.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.subscribe();
            let _ = open.wait_for(|open| *open).await;
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

struct Fixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    store: &'static GatedStore,
    sources: &'static LocalObjectStore,
    spool: &'static SpoolQueue,
    ingestor: tokio::sync::Mutex<Ingestor<'static>>,
    context: FindingAppendContext<'static>,
    request: FindingAppendRequest,
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// An ingest over a gated part store and one published, signed finding part
/// whose append request is ready (the detect side of the protocol).
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let store = leak(GatedStore {
        inner: LocalObjectStore::new(root.join("store")).unwrap(),
        pattern: std::sync::Mutex::new(None),
        open: tokio::sync::watch::channel(true).0,
        blocked_gets: AtomicUsize::new(0),
    });
    std::fs::create_dir_all(root.join("sources/bronze")).unwrap();
    let sources = leak(LocalObjectStore::new(root.join("sources")).unwrap());
    let spool = leak(SpoolQueue::new(root.join("spool"), TENANT).unwrap());
    let signer: &'static LocalPartSigner = leak(LocalPartSigner::new("lab-signer-gate", SigningKey::from_bytes(&[9; 32])).unwrap());
    let trusted = signer.trusted();

    let compact = serde_json::json!({
        "id":"f1", "timestamp_us":T0_US, "entity":"alice@example.com",
        "stamped_entity_type":"email", "risk_score":75, "rule_id":"r1",
        "rule_name":"test", "severity":"high", "origin_source_types":["auth"], "mitre_tactics":[]
    });
    let ocsf = serde_json::json!({
        "class_uid":2004, "time":T0_US / 1000,
        "metadata":{"uid":"f1","tenant_uid":TENANT,"log_source":"detections"},
        "unmapped":{}
    });
    let receipt = FindingReceipt::new(TENANT, "f1", &compact, &ocsf).unwrap();
    let source = receipt.source().unwrap();
    let receipt_bytes = receipt.bytes().unwrap();
    assert!(store.put_if_absent(&source.key, &receipt_bytes).await.unwrap());
    let parsed: CompactFinding = serde_json::from_value(compact).unwrap();
    let mut event = finding_event(&ocsf, &parsed).unwrap();
    event["time"] = serde_json::Value::String("2026-09-26T18:00:00.000000Z".into());
    let schema = Arc::new(infer_schema(&[&event]).unwrap());
    let now_ms = T0_US / 1000;
    let draft = PartDraft {
        tenant_id: TENANT.into(), signer_key_id: signer.key_id().into(), level: Level::L0,
        event_hour: event_hour_of(T0_US), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
        schema: schema.clone(),
        inputs: PartInputs::Sources { sources: vec![SourceObject {
            key: source.key.clone(), version: source.version.clone(), sha256: source.sha256.clone(),
            bytes: receipt_bytes.len() as u64, rows: 1, edge_sha256: None,
        }], edge_log: None },
        admission: Some(Admission { ocsf_version: crate::iceberg::OCSF_VERSION.into(),
            admission_contract: "finding-outbox-v1".into(), feed_pins: BTreeMap::new() }),
        rows_in: 1, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
    };
    let batch = decode(schema.clone(), &[&event]).unwrap();
    let mut writer = PartWriter::create(&root, draft, PartialSource::FromFindings, now_ms, 1).unwrap();
    writer.write(&batch).unwrap();
    let finished = writer.finish().unwrap();
    let refs: Vec<PartRef> = publish_parts(store, signer, &trusted, &[finished]).await.unwrap();

    let mut cfg = IngestConfig::new(TENANT, root.join("ingest"));
    cfg.flush_interval_override_ms = Some(1_000);
    let ingestor = Ingestor::open(cfg, store, sources, spool, signer, trusted,
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    let context = ingestor.finding_context();
    let request = FindingAppendRequest {
        tenant_id: TENANT.into(), writer_epoch: context.writer_epoch,
        schema: LogSchema::from_arrow(&schema).unwrap(), parts: refs, receipts: vec![source],
        deadline_unix_ms: None,
    };
    Fixture { _dir: dir, root, store, sources, spool, ingestor: tokio::sync::Mutex::new(ingestor), context, request }
}

fn copy(request: &FindingAppendRequest) -> FindingAppendRequest {
    FindingAppendRequest {
        tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
        parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
    }
}

fn gate(queue_depth: usize, deadline_ms: u64) -> FindingGate {
    FindingGate::new(FindingGateConfig { queue_depth, deadline: Duration::from_millis(deadline_ms), ..FindingGateConfig::default() })
}

/// One bronze parquet object of `rows` authentication events, delivered.
fn deliver_bronze(fx: &Fixture, name: &str, rows: usize) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut json = Vec::new();
    for i in 0..rows {
        let time = chrono::DateTime::from_timestamp_micros(T0_US + i as i64 * 1_000_000).unwrap();
        let raw = format!("raw {name}-{i} host-{i} logon token{i}");
        serde_json::to_writer(&mut json, &serde_json::json!({
            "activity_id": 1, "activity_name": "Logon",
            "actor": {"user": {"name": format!("USER{i}")}},
            "category_name": "Identity & Access Management", "category_uid": 3,
            "class_name": "Authentication", "class_uid": 3002,
            "message": format!("Failed logon for user{i} from 10.0.0.{i}"),
            "raw_data": raw, "raw_data_size": raw.len(),
            "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
                "product": {"name": "fixture", "vendor_name": "nano"},
                "tenant_uid": TENANT, "uid": format!("{name}-{i}"), "version": "1.9.0"},
            "severity": "Informational", "severity_id": 1,
            "src_endpoint": {"ip": format!("10.0.0.{i}"), "hostname": format!("ws-{i}.corp.local")},
            "dst_endpoint": {"ip": format!("192.168.1.{i}")},
            "user": {"name": format!("user{i}"), "uid": format!("S-1-5-21-{i}")},
            "status": "Failure", "status_id": 2,
            "time": time.to_rfc3339(),
            "type_uid": 300201
        })).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut std::io::Cursor::new(json.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema)).build(std::io::Cursor::new(json)).unwrap();
    let key = format!("bronze/{name}.parquet");
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let file = std::fs::File::create(fx.root.join("sources").join(&key)).unwrap();
        writer.get_or_insert_with(|| parquet::arrow::ArrowWriter::try_new(file, batch.schema(), None).unwrap())
            .write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
    fx.spool.deliver(&SourceNotice {
        tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
        notified_at_ms: T0_US / 1000,
    }).unwrap();
    let _ = fx.sources;
}

async fn live_parts(fx: &Fixture) -> usize {
    load_log(&fx.store.inner, TENANT).await.unwrap().parts().count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_finding_append_never_stops_part_ingestion() {
    let fx = fixture().await;
    let gate = gate(4, 1_500);
    // Detect's append hangs reading its receipt (a slow R2, a genesis scan).
    fx.store.block("finding-outbox/receipts/");
    let started = Instant::now();
    let append = {
        let admitted = gate.admit().unwrap();
        gate.append(admitted, &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000)
    };
    let ingest = async {
        // Meanwhile the ingest loop admits and flushes a source into a part.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(fx.store.blocked_gets.load(Ordering::SeqCst) > 0, "the append is blocked in the store");
        deliver_bronze(&fx, "src-1", 5);
        let mut ingestor = tokio::time::timeout(Duration::from_millis(200), fx.ingestor.lock()).await
            .expect("the ingestor lock is free while an append is blocked");
        let now_ms = T0_US / 1000;
        let report = ingestor.tick(now_ms).await.unwrap();
        assert_eq!(report.admitted_rows, 5, "{report:?} {:?}", ingestor.health());
        assert_eq!(ingestor.tick(now_ms + 2_000).await.unwrap().flushed_parts, 1);
        started.elapsed()
    };
    let (appended, ingested_after) = tokio::join!(append, ingest);
    assert!(ingested_after < Duration::from_millis(1_500), "ingestion finished before the append's deadline");
    let error = appended.expect_err("a blocked append is refused at its deadline");
    assert!(matches!(error.downcast_ref::<FindingRefused>(), Some(FindingRefused::Deadline(_))), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(3), "refused promptly, not after the store recovers");
    // Only the source part is in the log; the finding stays in detect's outbox.
    assert_eq!(live_parts(&fx).await, 1);
    fx.store.release();
    let admitted = gate.admit().unwrap();
    gate.append(admitted, &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await
        .expect("the retry lands once the store answers");
    assert_eq!(live_parts(&fx).await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_or_a_busy_ingest_loop_refuses_quickly_and_loses_nothing() {
    let fx = fixture().await;
    let gate = gate(1, 300);
    let held = gate.admit().unwrap();
    let started = Instant::now();
    assert!(matches!(gate.admit(), Err(FindingRefused::QueueFull(1))), "overload refuses at once");
    assert!(started.elapsed() < Duration::from_millis(50));
    // A long tick holds the ingestor: the append waits at most its deadline.
    let busy = fx.ingestor.lock().await;
    let error = gate.append(held, &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await
        .expect_err("refused while the ingest loop holds the ingestor");
    assert!(matches!(error.downcast_ref::<FindingRefused>(), Some(FindingRefused::Deadline("waiting for the ingest loop"))), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(busy);
    // Nothing was written: no attempt marker, so the retry needs no proof.
    let marker = finding_attempt_key(TENANT, &fx.request.receipts[0]).unwrap();
    assert!(fx.store.inner.get(&marker).await.unwrap().is_none());
    let admitted = gate.admit().expect("the refused append freed its slot");
    let first = gate.append(admitted, &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await.unwrap();
    assert_eq!(live_parts(&fx).await, 1);
    // A lost acknowledgement: the retry proves the replay, appends nothing.
    let replay = gate.append(gate.admit().unwrap(), &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await.unwrap();
    assert_eq!(replay, first);
    assert_eq!(live_parts(&fx).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_replay_proof_runs_without_the_lock_and_finishes_for_the_retry() {
    let fx = fixture().await;
    let gate = gate(4, 400);
    // A marker from an append that never committed: the log must decide.
    let marker = finding_attempt_key(TENANT, &fx.request.receipts[0]).unwrap();
    assert!(fx.store.inner.put_if_absent(&marker, &serde_json::to_vec(&fx.request.receipts[0]).unwrap()).await.unwrap());
    // The part-log scan is slow (the 30k-entry genesis scan).
    fx.store.block("/log/entries/");
    let append = gate.append(gate.admit().unwrap(), &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000);
    let probe = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(fx.ingestor.try_lock().is_ok(), "the proof never holds the ingestor");
    };
    let (error, ()) = tokio::join!(append, probe);
    let error = error.expect_err("the proof outlived the deadline");
    assert!(matches!(error.downcast_ref::<FindingRefused>(), Some(FindingRefused::Deadline(_))), "{error:#}");
    assert_eq!(gate.proofs_held(), 1, "the proof keeps running for the retry");
    fx.store.release();
    let response = gate.append(gate.admit().unwrap(), &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await
        .expect("the retry uses the finished proof and commits");
    assert_eq!(gate.proofs_held(), 0);
    assert_eq!(live_parts(&fx).await, 1);
    let replay = gate.append(gate.admit().unwrap(), &fx.ingestor, &fx.context, copy(&fx.request), || T0_US / 1000).await.unwrap();
    assert_eq!(replay, response, "a later retry is a replay, not a second Add");
}
