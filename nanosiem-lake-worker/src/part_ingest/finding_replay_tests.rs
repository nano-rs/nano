// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4656: the ops finding-replay livelock (2026-10-26). An append was
//! interrupted during a control roll; then a cell roll restarted both roles.
//! Every replay proof re-read the 57.8k-entry part log from seq 0 (~11 min),
//! longer than ingest's append deadline. Ingest refused, detect retried, the
//! scan restarted: ~474k R2 GETs/h and no finding delivered for hours.
//!
//! These tests drive the production constructors (`Ingestor::open`,
//! `FindingGate::new`, `publish_parts`, `committed_receipts`) over a log with
//! thousands of entries and count part-log entry GETs.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::discovery::SpoolQueue;
use crate::part_ingest::finding_floors::{floor_prefix, put_floor};
use crate::part_ingest::finding_outbox::{committed_receipts, FindingReceipt};
use crate::part_ingest::ingest::{seed_schema, IngestConfig};
use crate::part_ingest::schema::{decode, infer_schema};
use crate::part_ingest::writer::{publish_parts, sort_by_time_uid, PartDraft, PartWriter, PartialSource};
use crate::part_query::risk::{finding_event, CompactFinding};
use crate::parts::levels::Level;
use crate::parts::part_log::{LocalObjectStore, LogEntry, LogOp, LogSchema, ObjectStore, PartLogWriter, PartRef, WriteHints};
use crate::parts::format::LogKeys;
use crate::parts::provenance::{Admission, LocalPartSigner, PartInputs, PartSigner, SourceObject};
use crate::parts::{event_hour_of, DedupWindow};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const TENANT: &str = "00000000-0000-4000-8000-000000004656";
/// Entries already in the log before the finding append (ops had 57.8k).
const HISTORY: u64 = 3_000;

/// Counts part-log entry GETs; can fail the next log-entry PUT before it
/// lands (an interrupted append) or after it lands (a lost acknowledgement),
/// and can hold entry GETs (a slow scan).
struct FaultStore {
    inner: LocalObjectStore,
    entry_gets: AtomicUsize,
    fail_entry_put_before: AtomicBool,
    fail_entry_put_after: AtomicBool,
    hold_entries: tokio::sync::watch::Sender<bool>,
}

impl FaultStore {
    fn take_gets(&self) -> usize {
        self.entry_gets.swap(0, Ordering::SeqCst)
    }

    /// Faults hit only the finding `Add` entry (not a schema entry before it).
    fn fault_before(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        if is_add(key, bytes) && self.fail_entry_put_before.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected: the cell was rolled before the entry PUT");
        }
        Ok(())
    }

    fn fault_after(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        if is_add(key, bytes) && self.fail_entry_put_after.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected: the entry landed but its acknowledgement was lost");
        }
        Ok(())
    }
}

fn is_add(key: &str, bytes: &[u8]) -> bool {
    key.contains("/log/entries/") && bytes.windows(12).any(|window| window == br#""kind":"add""#)
}

#[async_trait]
impl ObjectStore for FaultStore {
    async fn modified_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
        self.inner.modified_ms(key).await
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        if key.contains("/log/entries/") {
            self.entry_gets.fetch_add(1, Ordering::SeqCst);
            let mut open = self.hold_entries.subscribe();
            let _ = open.wait_for(|held| !*held).await;
        }
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.fault_before(key, bytes)?;
        let created = self.inner.put_if_absent(key, bytes).await?;
        self.fault_after(key, bytes)?;
        Ok(created)
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.fault_before(key, bytes)?;
        let created = self.inner.put_if_absent_with(key, bytes, hints).await?;
        self.fault_after(key, bytes)?;
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

struct World {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    store: &'static FaultStore,
    spool: &'static SpoolQueue,
    signer: &'static LocalPartSigner,
    now_ms: i64,
}

/// A tenant log with [`HISTORY`] entries (genesis + schema entries).
async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let store = leak(FaultStore {
        inner: LocalObjectStore::new(root.join("store")).unwrap(),
        entry_gets: AtomicUsize::new(0),
        fail_entry_put_before: AtomicBool::new(false),
        fail_entry_put_after: AtomicBool::new(false),
        hold_entries: tokio::sync::watch::channel(false).0,
    });
    let spool = leak(SpoolQueue::new(root.join("spool"), TENANT).unwrap());
    let signer = leak(LocalPartSigner::new("lab-signer-4656", SigningKey::from_bytes(&[46; 32])).unwrap());
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut log = PartLogWriter::open(&store.inner, TENANT, 1, &seed_schema(), now_ms).await.unwrap();
    let schema = LogSchema::from_arrow(&seed_schema()).unwrap();
    for _ in 1..HISTORY {
        log.append(LogOp::Schema { schema: schema.clone() }, now_ms).await.unwrap();
    }
    assert_eq!(log.live().head().unwrap().0, HISTORY - 1);
    World { _dir: dir, root, store, spool, signer, now_ms }
}

async fn open_ingest(world: &World, name: &str) -> Ingestor<'static> {
    let mut cfg = IngestConfig::new(TENANT, world.root.join(name));
    cfg.flush_interval_override_ms = Some(1_000);
    Ingestor::open(cfg, world.store, &world.store.inner, world.spool, world.signer, world.signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), world.now_ms).await.unwrap()
}

/// Detect's side: receipts and one signed finding part for `ids`, and the
/// append request naming them.
async fn findings(world: &World, ids: &[&str], epoch: u64) -> FindingAppendRequest {
    let time_us = (world.now_ms - 3_600_000) * 1_000;
    let mut sources = Vec::new();
    let mut events = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let compact = serde_json::json!({
            "id":id, "timestamp_us":time_us + i as i64, "entity":"alice@example.com",
            "stamped_entity_type":"email", "risk_score":40, "rule_id":"rule-1",
            "rule_name":"fixture", "severity":"medium", "origin_source_types":["auth"], "mitre_tactics":[]
        });
        let ocsf = serde_json::json!({
            "class_uid":2004, "time":time_us / 1000,
            "metadata":{"uid":id,"tenant_uid":TENANT,"log_source":"detections"},
            "unmapped":{}
        });
        let receipt = FindingReceipt::new(TENANT, id, &compact, &ocsf).unwrap();
        let source = receipt.source().unwrap();
        let bytes = receipt.bytes().unwrap();
        world.store.inner.put_if_absent(&source.key, &bytes).await.unwrap();
        let parsed: CompactFinding = serde_json::from_value(compact).unwrap();
        let mut event = finding_event(&ocsf, &parsed).unwrap();
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(time_us + i as i64).unwrap();
        event["time"] = serde_json::Value::String(at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        sources.push((source, bytes.len() as u64));
        events.push(event);
    }
    let refs = events.iter().collect::<Vec<_>>();
    let schema = Arc::new(infer_schema(&refs).unwrap());
    let draft = PartDraft {
        tenant_id: TENANT.into(), signer_key_id: world.signer.key_id().into(), level: Level::L0,
        event_hour: event_hour_of(time_us), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
        schema: schema.clone(),
        inputs: PartInputs::Sources { sources: sources.iter().map(|(source, bytes)| SourceObject {
            key: source.key.clone(), version: source.version.clone(), sha256: source.sha256.clone(),
            bytes: *bytes, rows: 1, edge_sha256: None,
        }).collect(), edge_log: None },
        admission: Some(Admission { ocsf_version: crate::iceberg::OCSF_VERSION.into(),
            admission_contract: "finding-outbox-v1".into(), feed_pins: BTreeMap::new() }),
        rows_in: ids.len() as u64, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
    };
    let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
    let work = world.root.join(format!("w-{}", ids.join("-")));
    std::fs::create_dir_all(&work).unwrap();
    let mut writer = PartWriter::create(&work, draft, PartialSource::FromFindings, world.now_ms, batch.num_rows() as u64).unwrap();
    writer.write(&batch).unwrap();
    let finished = writer.finish().unwrap();
    let parts: Vec<PartRef> = publish_parts(&world.store.inner, world.signer, &world.signer.trusted(), &[finished]).await.unwrap();
    FindingAppendRequest {
        tenant_id: TENANT.into(), writer_epoch: epoch, schema: LogSchema::from_arrow(&schema).unwrap(),
        parts, receipts: sources.into_iter().map(|(source, _)| source).collect(), deadline_unix_ms: None,
    }
}

fn copy(request: &FindingAppendRequest) -> FindingAppendRequest {
    FindingAppendRequest {
        tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
        parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
    }
}

fn gate(deadline: Duration, ttl: Duration) -> FindingGate {
    FindingGate::new(FindingGateConfig { deadline, proof_ttl: ttl, ..FindingGateConfig::default() })
}

/// Ground truth, read from genesis with no floor: every seq whose `Add`
/// consumed `source`.
async fn consumptions(store: &LocalObjectStore, source: &SourceRef) -> Vec<u64> {
    let keys = LogKeys::new(TENANT).unwrap();
    let mut seqs = Vec::new();
    for seq in 0.. {
        let Some(bytes) = store.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            if consumed.iter().any(|item| item == source) {
                seqs.push(seq);
            }
        }
    }
    seqs
}

async fn head(store: &LocalObjectStore) -> u64 {
    crate::parts::part_log::load_log(store, TENANT).await.unwrap().head().unwrap().0
}

/// The ops incident, both ways an append can be cut by a roll. After a
/// restart of BOTH roles (fresh ingestor, fresh gate, fresh caches), the
/// replay finishes inside one append deadline, reads O(new entries) of the
/// part log rather than O(log), and every finding is consumed exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_append_cut_by_a_roll_is_proven_after_a_restart_of_both_roles_within_one_deadline() {
    for lost_ack in [false, true] {
        let world = world().await;
        let request = findings(&world, &["f1", "f2", "f3"], 1).await;
        let ingestor = tokio::sync::Mutex::new(open_ingest(&world, "ingest-a").await);
        let context = ingestor.lock().await.finding_context();
        let first_gate = gate(Duration::from_secs(5), Duration::from_secs(600));
        if lost_ack {
            world.store.fail_entry_put_after.store(true, Ordering::SeqCst);
        } else {
            world.store.fail_entry_put_before.store(true, Ordering::SeqCst);
        }
        let cut = first_gate.append(first_gate.admit().unwrap(), &ingestor, &context, copy(&request), || world.now_ms).await;
        assert!(cut.is_err(), "the roll cut the append");
        let landed = consumptions(&world.store.inner, &request.receipts[0]).await;
        assert_eq!(landed.len(), usize::from(lost_ack), "lost_ack={lost_ack}: {landed:?}");
        let before = head(&world.store.inner).await;
        assert!(before >= HISTORY - 1);

        // The cell roll: both roles restart with nothing in memory.
        drop((ingestor, context, first_gate));
        world.store.take_gets();

        // detect's drain proof (the same call publish_claimed makes).
        let trusted = world.signer.trusted();
        let committed = committed_receipts(world.store, TENANT, &request.receipts, &trusted).await.unwrap();
        let detect_gets = world.store.take_gets();
        assert_eq!(committed.len(), if lost_ack { 3 } else { 0 }, "lost_ack={lost_ack}");
        assert!(detect_gets <= 2 * 32 + 1, "detect read {detect_gets} entries of a {before}-entry log (lost_ack={lost_ack})");

        // ingest's gate after the restart: one deadline, bounded reads.
        let ingestor = tokio::sync::Mutex::new(open_ingest(&world, "ingest-b").await);
        world.store.take_gets();
        let context = ingestor.lock().await.finding_context();
        let deadline = Duration::from_secs(2);
        let fresh_gate = gate(deadline, Duration::from_secs(600));
        let started = Instant::now();
        let response = fresh_gate.append(fresh_gate.admit().unwrap(), &ingestor, &context, copy(&request), || world.now_ms)
            .await.expect("the retry lands inside one deadline");
        assert!(started.elapsed() < deadline);
        let ingest_gets = world.store.take_gets();
        assert!(ingest_gets <= 2 * 32 + 1 + 8, "ingest read {ingest_gets} entries of a {before}-entry log (lost_ack={lost_ack})");

        // Exactly once, from genesis ground truth: each receipt consumed by
        // one Add, and the retry acknowledges that Add.
        for source in &request.receipts {
            let seqs = consumptions(&world.store.inner, source).await;
            assert_eq!(seqs, vec![response.seq], "lost_ack={lost_ack}: {} consumed at {seqs:?}", source.key);
        }
        if lost_ack {
            assert_eq!(response.seq, before, "the lost Add is replayed, not appended again");
        } else {
            assert_eq!(response.seq, before + 1, "the cut append is appended once");
        }
        // A later retry of the same request is a replay as well.
        let again = fresh_gate.append(fresh_gate.admit().unwrap(), &ingestor, &context, copy(&request), || world.now_ms)
            .await.unwrap();
        assert_eq!(again, response);
        assert_eq!(consumptions(&world.store.inner, &request.receipts[0]).await, vec![response.seq]);
    }
}

/// The resume position is the WEAKEST floor of the wanted receipts: one
/// receipt's later floor never hides another's earlier consumption.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_resumes_after_the_weakest_floor_and_a_lying_floor_fails_stop() {
    let world = world().await;
    let mut ingestor = open_ingest(&world, "ingest").await;
    let first = findings(&world, &["a1"], 1).await;
    let a = ingestor.append_finding(copy(&first), world.now_ms).await.unwrap();
    let late = findings(&world, &["b1"], 1).await;
    let b = ingestor.append_finding(copy(&late), world.now_ms).await.unwrap();
    assert!(b.seq > a.seq);
    let (ra, rb) = (first.receipts[0].clone(), late.receipts[0].clone());
    let trusted = world.signer.trusted();
    let keys = LogKeys::new(TENANT).unwrap();
    let sha_of = |seq: u64| {
        let store = &world.store.inner;
        let key = keys.entry(seq);
        async move { crate::parts::sha256_hex(&store.get(&key).await.unwrap().unwrap()) }
    };
    // b1 is known absent through b's predecessor; a1 only through its own.
    put_floor(&world.store.inner, TENANT, b.seq - 1, &sha_of(b.seq - 1).await, &[rb.clone()]).await.unwrap();
    world.store.take_gets();
    let found = committed_receipts(world.store, TENANT, &[ra.clone(), rb.clone()], &trusted).await.unwrap();
    assert_eq!(found.get(&ra.key).map(|(seq, _)| *seq), Some(a.seq), "a1 is found below b1's floor");
    assert_eq!(found.get(&rb.key).map(|(seq, _)| *seq), Some(b.seq), "b1 is found right after its floor");
    assert!(world.store.take_gets() <= 2 * 32 + 1, "resumed after a1's commit floor, not genesis");

    // A floor at or above a real consumption is a lie. When a weaker floor
    // makes the scan pass the consumption, it fails stop: never an ack.
    // (Floors are trusted like checkpoints and markers: only this tenant's
    // ingest and detect write them, under its own prefix.)
    put_floor(&world.store.inner, TENANT, a.seq, &a.entry_sha256, &[ra.clone()]).await.unwrap();
    let c = findings(&world, &["c1"], 1).await;
    let rc = c.receipts[0].clone();
    put_floor(&world.store.inner, TENANT, a.seq - 1, &sha_of(a.seq - 1).await, &[rc.clone()]).await.unwrap();
    let error = committed_receipts(world.store, TENANT, &[ra.clone(), rc], &trusted).await.unwrap_err();
    assert!(format!("{error:#}").contains("below its replay floor"), "{error:#}");
    // A floor whose entry digest differs is refused, not resumed from.
    let prefix = floor_prefix(TENANT).unwrap();
    for key in world.store.inner.list(&prefix).await.unwrap() {
        world.store.inner.delete(&key).await.unwrap();
    }
    put_floor(&world.store.inner, TENANT, a.seq - 1, &"0".repeat(64), &[ra.clone()]).await.unwrap();
    let error = committed_receipts(world.store, TENANT, &[ra], &trusted).await.unwrap_err();
    assert!(format!("{error:#}").contains("does not match its entry"), "{error:#}");
}

/// The livelock itself: a proof longer than the deadline AND longer than
/// the proof TTL. Each retry waits on the running proof or resumes from its
/// floors; the log is read about once in total, never once per retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_of_a_slow_proof_never_restart_the_scan_from_genesis() {
    let world = world().await;
    let ingestor = open_ingest(&world, "ingest").await;
    // An attempted receipt with no floor at all (written before this fix):
    // its marker exists, its floor does not, its Add never landed.
    let request = findings(&world, &["s1", "s2"], 1).await;
    let now_ms = world.now_ms;
    crate::part_ingest::finding_attempts::put_attempt_batch(world.store, TENANT, &request.receipts, now_ms,
        &Default::default()).await.unwrap();
    let context = ingestor.finding_context();
    let ingestor = tokio::sync::Mutex::new(ingestor);
    world.store.take_gets();
    // Short deadline, shorter TTL: the ops shape (40 s deadline, 600 s TTL
    // counted from the start of an ~11 min scan).
    let gate = gate(Duration::from_millis(300), Duration::from_millis(1));
    world.store.hold_entries.send_replace(true);
    for _ in 0..3 {
        let refused = gate.append(gate.admit().unwrap(), &ingestor, &context, copy(&request), || now_ms).await;
        let error = refused.expect_err("the proof outlives the deadline");
        assert!(matches!(error.downcast_ref::<FindingRefused>(), Some(FindingRefused::Deadline(_))), "{error:#}");
        assert_eq!(gate.proofs_held(), 1, "one proof, still running");
    }
    world.store.hold_entries.send_replace(false);
    // Let the background proof read the whole log and finish (past its
    // TTL), then retry: the ops shape, where every retry arrived after the
    // previous proof had ended.
    let waited = Instant::now();
    while (world.store.entry_gets.load(Ordering::SeqCst) as u64) < HISTORY {
        assert!(waited.elapsed() < Duration::from_secs(30), "the background proof stalled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let response = gate.append(gate.admit().unwrap(), &ingestor, &context, copy(&request), || now_ms).await
        .expect("the retry resumes from the floor the finished proof recorded");
    let gets = world.store.take_gets() as u64;
    assert!(gets < HISTORY + 4 * 32, "{gets} entry GETs for a {HISTORY}-entry log: the scan restarted");
    assert!(gets >= HISTORY - 1, "the first proof had no floor and read the log once");
    for source in &request.receipts {
        assert_eq!(consumptions(&world.store.inner, source).await, vec![response.seq]);
    }
}

/// A commit floor is written only after the writer's double-consume check:
/// a repeat the writer refuses must never leave a floor above the Add that
/// already consumed its receipts (a later proof would resume past that Add,
/// call it absent, and let the finding be sent again).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_repeat_commit_records_no_floor_above_the_consuming_add() {
    let world = world().await;
    let mut ingestor = open_ingest(&world, "ingest").await;
    let request = findings(&world, &["d1"], 1).await;
    let landed = ingestor.append_finding(copy(&request), world.now_ms).await.unwrap();
    drop(ingestor);
    // The marker listing missed the attempt (clock skew, a lost listing):
    // the repeat reaches the commit with no replay proof.
    let markers = crate::part_ingest::finding_attempts::batch_prefix(TENANT).unwrap();
    for key in world.store.inner.list(&markers).await.unwrap() {
        world.store.inner.delete(&key).await.unwrap();
    }
    let mut ingestor = open_ingest(&world, "ingest-again").await;
    let error = ingestor.append_finding(copy(&request), world.now_ms).await.unwrap_err();
    assert!(error.chain().any(|cause| cause.downcast_ref::<crate::parts::part_log::DoubleConsume>().is_some()), "{error:#}");
    let found = committed_receipts(world.store, TENANT, &request.receipts, &world.signer.trusted()).await.unwrap();
    assert_eq!(found.get(&request.receipts[0].key).map(|(seq, _)| *seq), Some(landed.seq),
        "the consuming Add is still found: no floor was recorded past it");
}
