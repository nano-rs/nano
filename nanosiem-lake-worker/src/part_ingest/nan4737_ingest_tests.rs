// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4737 (NAN-4689 soak): behind, a pipelined flush's prevalence apply
//! (1.93 s of its 2.5 s serial commit) runs beside the next admission's
//! parse instead of on the commit. These drive the production path
//! (`Ingestor::open`, the cell's background handles, `tick`) and hold the
//! invariants: an ack never precedes the durable `add`; every committed row
//! is in the prevalence state exactly once, including across a crash between
//! the append and the deferred apply; dedupe is unchanged; at most one apply
//! is deferred and it lands before the next stamp.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::discovery::AckCounts;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

const TENANT: &str = "47370000-0000-4000-8000-000000000001";
const DAY0_S: i64 = 1_790_294_400;
const OBJECTS: usize = 24;
const ROWS: usize = 40;
/// Every row's destination: its occurrences in the state count the rows
/// applied (a double apply or a miss changes the count).
const COUNTED_IP: &str = "8.8.4.4";

fn event(object: usize, row: usize, time_s: i64) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(time_s, 0).unwrap();
    let uid = format!("nan4737-{object:03}-{row:04}");
    let raw = format!("raw {uid}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", row % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("logon {uid}"), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.0.{}", row % 250), "hostname": format!("ws-{object}-{}.corp.local", row % 3)},
        "dst_endpoint": {"ip": COUNTED_IP},
        "user": {"name": format!("user{}", row % 5), "uid": format!("S-1-5-21-{}", row % 5)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": 300201
    })
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema)).build(std::io::Cursor::new(lines)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap())
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: &'static LocalPartSigner,
    background: &'static LocalObjectStore,
}

/// `OBJECTS` objects of `ROWS` rows, plus a redelivery of object 3 (the
/// same uids in a new object: dedupe must keep it out of the state).
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer: &'static LocalPartSigner = Box::leak(Box::new(
        LocalPartSigner::new("lab-signer-nan4737", ed25519_dalek::SigningKey::from_bytes(&[37; 32])).unwrap()));
    // The cell hands ingest 'static handles for background build/publish.
    let background: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.join("parts")).unwrap()));
    for object in 0..OBJECTS {
        let at = DAY0_S + 2_400 + object as i64 * 20;
        let events = (0..ROWS).map(|row| event(object, row, at - 5)).collect::<Vec<_>>();
        let key = format!("bronze/{at}-{object:03}.parquet");
        write_bronze(&root.join("sources").join(&key), &events);
        spool.deliver(&notice(&key, at)).unwrap();
        if object == 3 {
            let key = format!("bronze/{}-{object:03}-redelivered.parquet", at + 7);
            write_bronze(&root.join("sources").join(&key), &events);
            spool.deliver(&notice(&key, at + 7)).unwrap();
        }
    }
    Fixture { _dir: dir, root, parts, sources, spool, signer, background }
}

fn notice(key: &str, at_s: i64) -> SourceNotice {
    SourceNotice { tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0, sha256: None,
        edge_sha256: None, notified_at_ms: at_s * 1_000 }
}

/// The spool, with every ack checked against the durable part log: each
/// acknowledged object must already be consumed by a committed `add`.
struct DurableAckQueue<'a> {
    spool: &'a SpoolQueue,
    parts: &'a LocalObjectStore,
    sources: &'a LocalObjectStore,
    keys: std::sync::Mutex<BTreeMap<String, String>>,
    acked: AtomicUsize,
}

#[async_trait::async_trait]
impl NoticeQueue for DurableAckQueue<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let pending = self.spool.pending(max).await?;
        let mut keys = self.keys.lock().unwrap();
        for (handle, notice) in &pending {
            keys.insert(handle.0.clone(), notice.key.clone());
        }
        Ok(pending)
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        let live = load_log(self.parts, TENANT).await?;
        for handle in handles {
            let key = self.keys.lock().unwrap().get(&handle.0).cloned().expect("an acked handle was pending");
            let bytes = self.sources.get(&key).await?.expect("source object");
            let source = SourceRef { key, version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "an ack before its add is durable: {}", source.key);
        }
        self.acked.fetch_add(handles.len(), Ordering::SeqCst);
        self.spool.ack(handles).await
    }
    async fn ack_skipped(&self, acks: &[(NoticeHandle, AckCounts)]) -> Result<()> {
        let handles = acks.iter().map(|(handle, _)| handle.clone()).collect::<Vec<_>>();
        self.spool.ack(&handles).await
    }
}

async fn open<'a>(fx: &'a Fixture, queue: &'a dyn NoticeQueue, clock_ms: i64) -> Ingestor<'a> {
    let mut config = IngestConfig::new(TENANT, fx.root.join("work"));
    config.flush_interval_override_ms = Some(10_000);
    // One object per admission: catch-up stays behind for many flushes.
    config.max_objects_per_admission = 1;
    let mut ingestor = Ingestor::open(config, &fx.parts, &fx.sources, queue, fx.signer, fx.signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock_ms).await.expect("ingest opens");
    ingestor.set_background_store(fx.background);
    ingestor.set_background_signer(fx.signer);
    ingestor
}

/// Occurrences of [`COUNTED_IP`] in the state's committed snapshot.
async fn counted(ingestor: &Ingestor<'_>) -> u64 {
    let mut probe = json!({"dst_endpoint": {"ip": COUNTED_IP}, "src_endpoint": {"hostname": "probe"}});
    ingestor.prevalence.as_ref().expect("prevalence is open").stamp(&mut probe).await.unwrap();
    probe["enrichments"][0]["data"]["total_occurrences"].as_u64().unwrap_or(0)
}

/// Tick until every notice is acked and nothing is buffered, in flight or
/// owed to the state.
async fn drain(ingestor: &mut Ingestor<'_>, fx: &Fixture, clock: &mut i64) {
    for _ in 0..400 {
        *clock += 11_000;
        ingestor.tick(*clock).await.unwrap();
        let idle = fx.spool.pending(1).await.unwrap().is_empty() && ingestor.health().buffered_rows == 0
            && ingestor.health().flushes_in_flight == 0;
        if idle && !ingestor.prevalence_pending() && ingestor.prevalence_status() == "stamping" {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("ingest did not drain: {}", ingestor.prevalence_status());
}

fn assert_rows_exactly_once(ingestor: &Ingestor<'_>) {
    let rows = ingestor.log.live().parts().map(|part| part.rows).sum::<u64>();
    assert_eq!(rows, (OBJECTS * ROWS) as u64, "every uid committed once (the redelivery deduped)");
}

/// Behind, a commit defers its apply, the next admission's parse runs beside
/// it, and its rows are stamped against a state that holds the deferred
/// flush. Every ack lands only after its `add` is durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_apply_lands_beside_the_next_admission_and_acks_wait_for_the_durable_add() {
    let fx = fixture();
    let queue = DurableAckQueue { spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
        keys: Default::default(), acked: AtomicUsize::new(0) };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = open(&fx, &queue, clock).await;
    let (mut deferred, mut overlapped) = (0, 0);
    for _ in 0..400 {
        clock += 11_000;
        let was_deferred = ingestor.prevalence_apply_deferred();
        let unstamped = ingestor.health().prevalence_unstamped_batches_total;
        let report = ingestor.tick(clock).await.unwrap();
        if was_deferred && report.admitted_rows > 0 {
            overlapped += 1;
            assert!(ingestor.prevalence_deferred.as_ref().is_none_or(|next| next.tick == ingestor.ingest_ticks),
                "the admission landed the earlier tick's deferred apply");
            assert_eq!(ingestor.health().prevalence_unstamped_batches_total, unstamped,
                "the admission beside a deferred apply is stamped, never skipped as owed");
        }
        if ingestor.prevalence_apply_deferred() {
            deferred += 1;
            let entry = ingestor.prevalence_deferred.as_ref().unwrap().seq;
            let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
            assert!(cursor.seq < entry, "deferred: the add is committed (and acked) but not yet applied");
            assert!(load_log(&fx.parts, TENANT).await.unwrap().head().is_some_and(|(head, _, _)| head >= entry),
                "the deferred add is in the durable log");
        }
        if fx.spool.pending(1).await.unwrap().is_empty() && ingestor.health().buffered_rows == 0
            && ingestor.health().flushes_in_flight == 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(deferred >= 2, "catch-up deferred its applies ({deferred})");
    assert!(overlapped >= 1, "an admission ran beside a deferred apply ({overlapped})");
    drain(&mut ingestor, &fx, &mut clock).await;
    assert!(!ingestor.prevalence_apply_deferred());
    assert!(queue.acked.load(Ordering::SeqCst) >= OBJECTS, "every add's objects acked (after durability)");
    assert_rows_exactly_once(&ingestor);
    assert_eq!(counted(&ingestor).await, (OBJECTS * ROWS) as u64, "every committed row applied exactly once");
}

/// A crash between the part-log append (acked) and the deferred apply: the
/// restarted ingest replays the committed `add` from the cursor exactly
/// once: no miss, no double count, and the redelivered object deduped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_between_the_append_and_the_deferred_apply_replays_it_exactly_once() {
    let fx = fixture();
    let queue = DurableAckQueue { spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
        keys: Default::default(), acked: AtomicUsize::new(0) };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = open(&fx, &queue, clock).await;
    let (mut crashed, mut deferrals) = (None, 0);
    for _ in 0..400 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
        if let Some(deferred) = &ingestor.prevalence_deferred {
            // The second deferral: the first was applied beside an
            // admission, so the state already holds adds the replay must
            // not count again.
            deferrals += 1;
            if deferrals == 2 {
                let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
                crashed = Some((deferred.seq, cursor.seq));
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let (entry, cursor) = crashed.expect("a commit deferred its apply after an applied one");
    assert!(cursor < entry);
    let acked = queue.acked.load(Ordering::SeqCst);
    assert!(acked > 0, "the deferred add's objects were acked: only the log can bring its rows back");
    // The crash: the process dies with the apply never started. The state
    // sees no write for the deferred entry.
    drop(ingestor);

    let mut ingestor = open(&fx, &queue, clock).await;
    drain(&mut ingestor, &fx, &mut clock).await;
    let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
    assert!(cursor.seq >= entry, "the restart replayed the deferred add");
    assert_rows_exactly_once(&ingestor);
    assert_eq!(counted(&ingestor).await, (OBJECTS * ROWS) as u64,
        "the deferred add applied exactly once across the crash (a miss or a double count changes this)");
}

/// A finding `Add` (`commit_finding`, between ticks) committed while a
/// flush's apply is deferred: the deferred entry is no longer the log head,
/// so landing it must not clear pending past the finding. The fast path
/// would apply only the deferred entry and clear pending, and the next
/// `Add`'s apply would move the cursor past the finding for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finding_committed_beside_a_deferred_apply_is_not_skipped() {
    use crate::part_ingest::finding_append::FindingAppendRequest;
    use crate::part_ingest::finding_outbox::FindingReceipt;
    use crate::part_ingest::schema::{decode, infer_schema};
    use crate::part_ingest::writer::{publish_parts, PartDraft, PartWriter, PartialSource};
    use crate::part_query::risk::{finding_event, CompactFinding};
    use crate::parts::levels::Level;
    use crate::parts::part_log::LogSchema;
    use crate::parts::provenance::{Admission, PartInputs, PartSigner, SourceObject};
    use crate::parts::{event_hour_of, DedupWindow};

    let fx = fixture();
    let queue = DurableAckQueue { spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
        keys: Default::default(), acked: AtomicUsize::new(0) };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = open(&fx, &queue, clock).await;
    for _ in 0..400 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
        if ingestor.prevalence_apply_deferred() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let deferred = ingestor.prevalence_deferred.as_ref().expect("catch-up deferred an apply").seq;

    // A signed finding part for this tenant, committed through the
    // production append (validate, register, `commit_finding`).
    let timestamp_us = (DAY0_S + 2_400) * 1_000_000;
    let compact = json!({
        "id": "f4737", "timestamp_us": timestamp_us, "entity": "alice@example.com",
        "stamped_entity_type": "email", "risk_score": 75, "rule_id": "r1",
        "rule_name": "test", "severity": "high", "origin_source_types": ["auth"], "mitre_tactics": []
    });
    let ocsf = json!({
        "class_uid": 2004, "time": timestamp_us / 1000,
        "metadata": {"uid": "f4737", "tenant_uid": TENANT, "log_source": "detections"},
        "unmapped": {}
    });
    let receipt = FindingReceipt::new(TENANT, "f4737", &compact, &ocsf).unwrap();
    let source = receipt.source().unwrap();
    let receipt_bytes = receipt.bytes().unwrap();
    assert!(fx.parts.put_if_absent(&source.key, &receipt_bytes).await.unwrap());
    let parsed: CompactFinding = serde_json::from_value(compact).unwrap();
    let mut finding = finding_event(&ocsf, &parsed).unwrap();
    finding["time"] = Value::String(chrono::DateTime::<chrono::Utc>::from_timestamp_micros(timestamp_us).unwrap()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string());
    let schema = Arc::new(infer_schema(&[&finding]).unwrap());
    let draft = PartDraft {
        tenant_id: TENANT.into(), signer_key_id: fx.signer.key_id().into(), level: Level::L0,
        event_hour: event_hour_of(timestamp_us), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
        schema: schema.clone(),
        inputs: PartInputs::Sources { sources: vec![SourceObject {
            key: source.key.clone(), version: source.version.clone(), sha256: source.sha256.clone(),
            bytes: receipt_bytes.len() as u64, rows: 1, edge_sha256: None,
        }], edge_log: None },
        admission: Some(Admission { ocsf_version: crate::iceberg::OCSF_VERSION.into(),
            admission_contract: "finding-outbox-v1".into(), feed_pins: BTreeMap::new() }),
        rows_in: 1, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
    };
    let drafts = fx.root.join("finding-drafts");
    std::fs::create_dir_all(&drafts).unwrap();
    let mut writer = PartWriter::create(&drafts, draft, PartialSource::FromFindings, clock, 1).unwrap();
    writer.write(&decode(schema.clone(), &[&finding]).unwrap()).unwrap();
    let refs = publish_parts(&fx.parts, fx.signer, &fx.signer.trusted(), &[writer.finish().unwrap()]).await.unwrap();
    let committed = ingestor.append_finding(FindingAppendRequest {
        tenant_id: TENANT.into(), writer_epoch: 1, schema: LogSchema::from_arrow(&schema).unwrap(),
        parts: refs, receipts: vec![source], deadline_unix_ms: None,
    }, clock).await.expect("the finding commits");
    assert!(committed.seq > deferred, "the finding follows the deferred add");
    assert!(ingestor.prevalence_pending(), "both adds are owed");

    // The deferral lands (as the next admission or the tick end would land
    // it): pending may clear only once the state holds the finding too.
    ingestor.finish_deferred_prevalence(clock).await;
    let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
    assert!(ingestor.prevalence_pending() || cursor.seq >= committed.seq,
        "pending cleared with the finding add unapplied (cursor {} < finding {})", cursor.seq, committed.seq);
    drain(&mut ingestor, &fx, &mut clock).await;
    let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
    assert!(cursor.seq >= committed.seq, "the finding add reached the state");
}
