// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2868 × NAN-2874: `ingest[T]` over the tenant edge log (lean tenant, no
//! bronze). A faithful in-memory DO drives the real `EdgeLogSource`; the part
//! log must chain every flush's range, and a restart resumes without loss or
//! duplicates.

use anyhow::Result;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::edge_log::*;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::dedup::read_time_uids;
use nanosiem_lake_worker::part_ingest::edge::{EdgeQueue, EdgeSegments};
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor};
use nanosiem_lake_worker::parts::format::{LogKeys, PartKeys};
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, LogEntry, LogOp, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, PartInputs, PartSigner, SignedProvenance};
use nanosiem_lake_worker::parts::{edge_log_genesis, edge_log_next_chain, sha256_hex};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const DAY0_S: i64 = 1_790_294_400;

fn event(uid: &str, time_s: i64, i: usize) -> Value {
    let time = chrono::DateTime::from_timestamp(time_s, (i as u32 % 1000) * 1_000_000).unwrap();
    let raw = format!("raw {uid} host-{} logon token{} mimikatz{}", i % 7, i % 13, if i % 97 == 0 { "-marker" } else { "" });
    json!({
        "activity_id": 1,
        "activity_name": "Logon",
        "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management",
        "category_uid": 3,
        "class_name": "Authentication",
        "class_uid": 3002,
        "message": format!("Failed logon for user{} from 10.0.{}.{}", i % 5, i % 3, i % 250),
        "raw_data": raw,
        "raw_data_size": raw.len(),
        "metadata": {
            "log_name": "security",
            "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"},
            "tenant_uid": TENANT,
            "uid": uid,
            "version": "1.9.0"
        },
        "severity": "Informational",
        "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 3, i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "user": {"name": format!("user{}", i % 5), "uid": format!("S-1-5-21-{}", i % 5)},
        "status": "Failure",
        "status_id": 2,
        "time": time.to_rfc3339(),
        "type_uid": 300201
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}


fn parquet_bytes(events: &[Value]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.parquet");
    write_bronze(&path, events);
    std::fs::read(path).unwrap()
}

#[derive(Default)]
struct DoState {
    segments: Vec<Segment>,
    epoch: u64,
    committed: u64,
    commits: Vec<(u64, String)>,
    /// Fail the next N commits (the Add landed, the DO commit did not).
    fail_commits: u32,
}

#[derive(Clone, Default)]
struct FakeDo(Arc<Mutex<DoState>>);

impl FakeDo {
    fn append(&self, key: &str, body: Vec<u8>) {
        let seq = self.0.lock().unwrap().segments.len() as u64 + 1;
        self.append_at(key, body, DAY0_S * 1_000 + seq as i64);
    }
    /// Append a segment the edge received at `received_at_ms` (NAN-4336:
    /// ingest clamps a row more than 5 min past its receipt to the receipt).
    fn append_at(&self, key: &str, body: Vec<u8>, received_at_ms: i64) {
        let mut s = self.0.lock().unwrap();
        let seq = s.segments.len() as u64 + 1;
        let prev = s.segments.last().map(|x| x.chain.clone()).unwrap_or_else(|| edge_log_genesis(TENANT));
        let sha = sha256_hex(&body);
        let chain = edge_log_next_chain(&prev, seq, key, &sha, body.len() as u64);
        s.segments.push(Segment { seq, key: key.into(), sha256: sha, length: body.len() as u64, prev_chain: prev, chain,
            received_at_ms, bytes: body });
    }
    fn committed(&self) -> u64 {
        self.0.lock().unwrap().committed
    }
}

#[async_trait]
impl EdgeLogTransport for FakeDo {
    async fn lease(&self, _consumer: &str, at: Option<u64>) -> Result<Lease> {
        let mut s = self.0.lock().unwrap();
        s.epoch += 1;
        let chain_at = |seq: u64| if seq == 0 { Some(edge_log_genesis(TENANT)) } else { s.segments.get(seq as usize - 1).map(|x| x.chain.clone()) };
        Ok(Lease {
            backlog_skip: None,
            kind: "ok".into(), epoch: s.epoch, committed_through: s.committed, committed_chain: chain_at(s.committed).unwrap(),
            last_part_id: None, head: s.segments.len() as u64, floor_seq: 0, floor_chain: edge_log_genesis(TENANT),
            mode: "do".into(), overflow_objects: 0, at_chain: at.and_then(chain_at), purge_seq: None, purge_chain: None,
        })
    }
    async fn pull(&self, epoch: u64, after: u64, max_bytes: u64, max_segments: u32) -> Result<PullOutcome> {
        let s = self.0.lock().unwrap();
        if epoch != s.epoch { return Ok(PullOutcome::Fenced); }
        let mut out = Vec::new();
        let mut total = 0;
        for seg in s.segments.iter().skip(after as usize).take(max_segments as usize) {
            if !out.is_empty() && total + seg.length > max_bytes { break; }
            total += seg.length;
            out.push(seg.clone());
        }
        Ok(PullOutcome::Batch(PullBatch { committed_through: s.committed, head: s.segments.len() as u64, mode: "do".into(),
            overflow_objects: 0, segments: out }))
    }
    async fn commit(&self, r: &CommitRequest) -> Result<CommitOutcome> {
        let mut s = self.0.lock().unwrap();
        if s.fail_commits > 0 {
            s.fail_commits -= 1;
            anyhow::bail!("injected: edge log commit lost");
        }
        if r.epoch != s.epoch { return Ok(CommitOutcome::Fenced); }
        if r.through == s.committed {
            let same = s.commits.last().is_some_and(|(t, id)| *t == r.through && *id == r.part_id);
            return Ok(if same { CommitOutcome::Replayed } else { CommitOutcome::Conflict { committed_through: s.committed } });
        }
        let ok = s.segments.get(r.through as usize - 1).is_some_and(|x| x.chain == r.through_chain);
        if r.through < s.committed || !ok { return Ok(CommitOutcome::Conflict { committed_through: s.committed }); }
        s.committed = r.through;
        s.commits.push((r.through, r.part_id.clone()));
        Ok(CommitOutcome::Committed)
    }
}

fn seg_key(i: usize) -> String {
    format!("bronze-v2/shard=0/tenant_id={TENANT}/{}-{i:05}.parquet", DAY0_S + 2_400 + i as i64)
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-edge-0001", SigningKey::from_bytes(&[13; 32])).unwrap()
}

async fn run_ingest(fake: &FakeDo, parts: &dyn ObjectStore, work: &Path, from: i64, ticks: usize) -> Result<()> {
    let live = load_log(parts, TENANT).await?;
    let point = live.edge_point().or(live.edge_ended()).cloned();
    let source = Arc::new(EdgeLogSource::open(fake.clone(), TENANT, "ingest", point.as_ref(), EdgeLogSourceConfig::default()).await?);
    let queue = EdgeQueue::new(source.clone(), TENANT);
    let segments = EdgeSegments::new(source);
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, work);
    cfg.flush_interval_override_ms = Some(10_000);
    cfg.max_objects_per_admission = 8;
    let mut ingestor = Ingestor::open(cfg, parts, &segments, &queue, &signer, signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), from).await?;
    let mut clock = from;
    for _ in 0..ticks {
        ingestor.tick(clock).await?;
        clock += 11_000;
    }
    ingestor.flush_now(clock).await?;
    Ok(())
}

async fn live_uids(parts: &LocalObjectStore) -> Vec<String> {
    let set = load_log(parts, TENANT).await.unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for i in 0..part.data_files as usize {
            let path = scratch.path().join(format!("{}-{i}", part.part_id));
            std::fs::write(&path, parts.get(&keys.data(i)).await.unwrap().unwrap()).unwrap();
            out.extend(read_time_uids(&path).unwrap().into_iter().map(|(_, u)| u));
        }
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn a_lean_tenant_ingests_the_edge_log_with_chained_ranges_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let fake = FakeDo::default();
    let mut expected = HashSet::new();
    let mut n = 0;
    for i in 1..=40 {
        if i == 7 {
            // A segment admission refuses (not OCSF): a skip of the next range.
            fake.append(&seg_key(i), parquet_bytes(&[json!({"not": "ocsf", "time": 1})]));
            continue;
        }
        let events = (0..5)
            .map(|r| {
                n += 1;
                let uid = format!("edge-{i:03}-{r}");
                expected.insert(uid.clone());
                event(&uid, DAY0_S + 2_400 + i as i64, n)
            })
            .collect::<Vec<_>>();
        fake.append(&seg_key(i), parquet_bytes(&events));
        if i == 20 {
            // Replay of segment 20's events in a new segment: all duplicates.
            fake.append(&seg_key(1_000 + i), parquet_bytes(&events));
        }
    }
    // First process: stops part-way (a few ticks), then a second resumes.
    run_ingest(&fake, &parts, &dir.path().join("w1"), (DAY0_S + 2_500) * 1_000, 1).await.unwrap();
    let first_commit = fake.committed();
    assert!(first_commit > 0 && first_commit < 41, "the first process committed part of the log: {first_commit}");
    run_ingest(&fake, &parts, &dir.path().join("w2"), (DAY0_S + 2_600) * 1_000, 20).await.unwrap();
    assert_eq!(fake.committed(), 41, "every segment is committed");

    let uids = live_uids(&parts).await;
    assert_eq!(uids.len(), expected.len(), "no loss, no duplicates");
    assert_eq!(uids.iter().collect::<HashSet<_>>().len(), uids.len());

    // The log chains the ranges (load_log enforces continuity) and every
    // add carries a range identical on its records.
    let set = load_log(&parts, TENANT).await.unwrap();
    assert_eq!(set.edge_point().unwrap().through_seq, 41);
    let keys = LogKeys::new(TENANT).unwrap();
    let mut adds = 0;
    for seq in 0.. {
        let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { parts: refs, edge_log, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            adds += 1;
            let range = edge_log.expect("every add carries its edge range");
            for part in refs {
                let pk = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
                let signed = SignedProvenance::verify_bytes(&parts.get(&pk.provenance()).await.unwrap().unwrap(), TENANT, &signer().trusted()).unwrap();
                let PartInputs::Sources { edge_log: Some(record_range), .. } = &signed.record.inputs else { panic!("record lacks the range") };
                assert_eq!(record_range, &range);
            }
        }
    }
    assert!(adds >= 2);
}

/// Part store whose part-data uploads can be refused (log entries still land),
/// to stop a flush after it built its part drafts but before its `Add`.
struct FaultyParts {
    inner: LocalObjectStore,
    refuse_parts: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl ObjectStore for FaultyParts {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        if self.refuse_parts.load(std::sync::atomic::Ordering::SeqCst) && !key.contains("/log/") {
            anyhow::bail!("injected: part upload failed");
        }
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

fn files_under(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| {
        let p = e.path();
        if std::fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false) { files_under(&p) } else { 1 }
    }).sum()).unwrap_or(0)
}

/// NAN-3000: the cell purges a removed tenant's whole local tree (ingest
/// work dir with its part drafts / spill) once it is drained. That loses
/// nothing in edge mode, because the DO commit (`committedThrough`) happens
/// only AFTER the parts are signed and uploaded AND the part-log `Add` that
/// consumes the range has landed:
///
/// 1. a consumer dies after pulling and building part drafts but before
///    the upload: nothing committed anywhere; the purge deletes the drafts;
///    the next consumer re-pulls the same segments from `committedThrough`;
/// 2. a consumer dies after the `Add` but before the DO commit: the next
///    consumer resumes from the PART LOG's edge point, reconciles the DO
///    commit, and never re-ingests those segments.
///
/// Result: every event exactly once (deterministic uids, no duplicates).
#[tokio::test(flavor = "current_thread")]
async fn purging_a_consumer_with_unuploaded_parts_loses_nothing_and_duplicates_nothing() {
    use nanosiem_lake_cell::tenant_dirs::{ensure_tenant_tree, purge_tenant_tree, tenant_tree_present};
    use nanosiem_lake_cell::uidmap::TenantIds;
    let dir = tempfile::tempdir().unwrap();
    let store = FaultyParts {
        inner: LocalObjectStore::new(dir.path().join("r2")).unwrap(),
        refuse_parts: std::sync::atomic::AtomicBool::new(true),
    };
    let fake = FakeDo::default();
    let mut expected = HashSet::new();
    let mut n = 0;
    for i in 1..=24 {
        let events = (0..4)
            .map(|r| {
                n += 1;
                let uid = format!("purge-{i:03}-{r}");
                expected.insert(uid.clone());
                event(&uid, DAY0_S + 2_400 + i as i64, n)
            })
            .collect::<Vec<_>>();
        fake.append(&seg_key(i), parquet_bytes(&events));
    }
    // The cell layout: <data_dir>/tenants/<T>/ingest is ingest's work dir.
    let tenants = dir.path().join("tenants");
    std::fs::create_dir(&tenants).unwrap();
    // SAFETY: geteuid/getegid never fail.
    let (u, g) = unsafe { (libc::geteuid(), libc::getegid()) };
    let ids = TenantIds { slot: 0, ingest_uid: u, query_uid: u, detect_uid: u, landing_uid: Some(u), gid: g };
    let work = tenants.join(TENANT).join("ingest");

    // 1. Cell A: pulls, builds part drafts, the upload fails. Removed, drained, purged.
    ensure_tenant_tree(&tenants, TENANT, &ids).unwrap();
    let err = run_ingest(&fake, &store, &work, (DAY0_S + 2_500) * 1_000, 1).await.unwrap_err();
    assert!(format!("{err:#}").contains("injected: part upload failed"), "{err:#}");
    assert_eq!(fake.committed(), 0, "nothing is committed upstream before the upload + Add");
    assert!(load_log(&store, TENANT).await.unwrap().edge_point().is_none(), "no Add landed");
    assert!(files_under(&work.join("parts")) > 0, "cell A left un-uploaded part drafts behind");
    let purged = purge_tenant_tree(&tenants, TENANT).unwrap();
    assert!(purged.cache_bytes > 0 && !tenant_tree_present(&tenants, TENANT).unwrap());

    // 2. Cell B: uploads and appends its Add, then loses the DO commit. Purged.
    store.refuse_parts.store(false, std::sync::atomic::Ordering::SeqCst);
    fake.0.lock().unwrap().fail_commits = 1;
    ensure_tenant_tree(&tenants, TENANT, &ids).unwrap();
    let err = run_ingest(&fake, &store, &work, (DAY0_S + 2_600) * 1_000, 1).await.unwrap_err();
    assert!(format!("{err:#}").contains("injected: edge log commit lost"), "{err:#}");
    let point = load_log(&store, TENANT).await.unwrap().edge_point().map(|p| p.through_seq).unwrap_or(0);
    assert!(point > fake.committed(), "the Add landed ({point}) ahead of the DO commit ({})", fake.committed());
    purge_tenant_tree(&tenants, TENANT).unwrap();

    // 3. Cell C: a fresh tree; re-pulls from committedThrough after reconciling.
    ensure_tenant_tree(&tenants, TENANT, &ids).unwrap();
    run_ingest(&fake, &store, &work, (DAY0_S + 2_700) * 1_000, 20).await.unwrap();
    assert_eq!(fake.committed(), 24, "every segment committed");
    let uids = live_uids(&store.inner).await;
    assert_eq!(uids.iter().collect::<HashSet<_>>().len(), uids.len(), "no duplicates");
    assert_eq!(uids.into_iter().collect::<HashSet<_>>(), expected, "no loss");
}

/// NAN-2992: the uid the lake storage stage derives for an edge-stamped HEC
/// event, mirroring `_ocsf_sink.toml`: sha256("nano-uid-v1:key:" + tenant +
/// ":" + receipt digest + ":" + ordinal), UUID-shaped with version 8.
fn stamped_uid(receipt: &str, ordinal: usize) -> String {
    let digest = sha256_hex(format!("nano-uid-v1:key:{TENANT}:{receipt}:{ordinal}").as_bytes());
    format!("{}-{}-8{}-a{}-{}", &digest[0..8], &digest[8..12], &digest[13..16], &digest[17..20], &digest[20..32])
}

/// NAN-2992 acceptance, lake side: a HEC batch Vector accepted but whose
/// receipt never committed is delivered again under the same Idempotency-Key.
/// Vector writes the second copy into a different edge segment (a new sink
/// batch), after the first copy was already ingested and committed by an
/// earlier process. With receipt-derived uids the redelivery adds zero rows,
/// while identical lines at different ordinals stay distinct events.
#[tokio::test(flavor = "current_thread")]
async fn a_redelivered_batch_after_a_lost_receipt_adds_zero_rows() {
    let dir = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let fake = FakeDo::default();
    let receipt = "a".repeat(64);
    let batch = (0..50)
        .map(|ordinal| {
            // Ordinals 10 and 11 carry the same line at the same time: two real events.
            let i = if ordinal == 11 { 10 } else { ordinal };
            event(&stamped_uid(&receipt, ordinal), DAY0_S + 3_000 + i as i64, i)
        })
        .collect::<Vec<_>>();
    let expected: HashSet<String> = batch
        .iter()
        .map(|row| row["metadata"]["uid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(expected.len(), 50, "ordinals keep identical lines distinct");
    fake.append(&seg_key(1), parquet_bytes(&batch));
    run_ingest(&fake, &parts, &dir.path().join("w1"), (DAY0_S + 3_100) * 1_000, 3).await.unwrap();
    assert_eq!(live_uids(&parts).await.len(), 50);

    // The redelivery lands later in its own segment, next to fresh traffic.
    let other = "b".repeat(64);
    let mut redelivery = batch.clone();
    redelivery.extend((0..5).map(|ordinal| event(&stamped_uid(&other, ordinal), DAY0_S + 3_060 + ordinal as i64, 100 + ordinal)));
    fake.append(&seg_key(2), parquet_bytes(&redelivery));
    run_ingest(&fake, &parts, &dir.path().join("w2"), (DAY0_S + 3_700) * 1_000, 3).await.unwrap();
    assert_eq!(fake.committed(), 2);

    let uids = live_uids(&parts).await;
    assert_eq!(uids.len(), 55, "the redelivered 50 add zero rows; the 5 new events land");
    assert_eq!(uids.iter().collect::<HashSet<_>>().len(), 55, "no duplicate uid is stored");
    assert!(expected.iter().all(|uid| uids.contains(uid)));
}

/// Plays the platform's `lake-parts:sign` body fence
/// (`MAX_LAKE_PARTS_SIGN_BODY_BYTES`): an over-cap body is refused whole,
/// like the owner's 413. Records every call's body size.
struct FencedOwner {
    inner: LocalPartSigner,
    bodies: Mutex<Vec<usize>>,
}

#[async_trait]
impl PartSigner for FencedOwner {
    fn key_id(&self) -> &str {
        self.inner.key_id()
    }
    async fn sign(
        &self,
        tenant_id: &str,
        records: &[nanosiem_lake_worker::parts::provenance::ProvenanceRecord],
    ) -> Result<Vec<nanosiem_lake_worker::parts::provenance::Ed25519Signature>> {
        use nanosiem_lake_worker::parts::provenance::{SignRequest, OWNER_SIGN_BODY_MAX_BYTES};
        let body = SignRequest::new(tenant_id, records)?.body_bytes()?;
        self.bodies.lock().unwrap().push(body);
        anyhow::ensure!(body <= OWNER_SIGN_BODY_MAX_BYTES, "lake-parts:sign refused: 413 Payload Too Large ({body} bytes)");
        self.inner.sign(tenant_id, records).await
    }
}

/// A segment key shaped like the edge sink's (`<unix>-<n>.parquet`).
fn backlog_seg_key(i: usize) -> String {
    format!("bronze-v2/shard=0/tenant_id={TENANT}/{}-{i:05}.parquet", DAY0_S + 3_000 + i as i64)
}

/// NAN-3006 (INGEST-STALL-D3C1): a restart leaves a backlog of 114+ edge
/// segments at 300 eps across 5 sources, straddling an hour boundary. The
/// resumed consumer flushes it as one L0 part per hour, every record naming
/// every segment (each record ≈ 40 KiB of base64, inline pre-fix). Split by
/// count only, that sign request was ~80+ KB and the
/// owner's 64 KiB fence refused it on every retry (ingest stalled). Every
/// call must stay under the fence and every segment must commit.
#[tokio::test(flavor = "current_thread")]
async fn a_restart_backlog_across_an_hour_boundary_signs_under_the_owner_body_cap() {
    use nanosiem_lake_worker::parts::provenance::{
        SignRequest, SignRequestPart, INLINE_RECORD_MAX_BASE64, OWNER_SIGN_BODY_MAX_BYTES, SIGN_REQUEST_BUDGET_BYTES,
    };
    let dir = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let fake = FakeDo::default();
    let owner = FencedOwner { inner: signer(), bodies: Mutex::new(Vec::new()) };
    let mut expected = HashSet::new();
    let mut n = 0;
    // 300 eps ≈ 750 rows per ~2.5 s Vector batch; rows do not change the
    // record size, so each segment carries a slice of them.
    let hour_end = DAY0_S + 3_600;
    let mut segment = |fake: &FakeDo, i: usize, n: &mut usize| {
        let events = (0..6)
            .map(|r| {
                *n += 1;
                let uid = format!("backlog-{i:04}-{r}");
                expected.insert(uid.clone());
                // Segments span hour_end - 150 s .. hour_end + ~150 s.
                let mut row = event(&uid, hour_end - 150 + (i as i64 * 5) / 2, *n);
                row["metadata"]["log_source"] = json!(["WINDOWS_EVENT", "SYSMON", "OKTA", "AWS_CLOUDTRAIL", "ZEEK"][i % 5]);
                row
            })
            .collect::<Vec<_>>();
        // The edge receives each segment just after its events (NAN-4336
        // clamps rows more than 5 min past receipt to it, which would fold
        // the whole backlog into the first hour).
        let received_at_ms = (hour_end - 150 + (i as i64 * 5) / 2 + 2) * 1_000;
        fake.append_at(&backlog_seg_key(i), parquet_bytes(&events), received_at_ms);
    };
    // The first process commits a few segments, then dies (a roll).
    for i in 1..=6 {
        segment(&fake, i, &mut n);
    }
    let from = (hour_end - 100) * 1_000;
    run_backlog(&fake, &parts, &owner, &dir.path().join("w1"), from, 1).await.unwrap();
    assert_eq!(fake.committed(), 6);
    // 114 more land while no consumer runs (the stall had 114 pending).
    for i in 7..=120 {
        segment(&fake, i, &mut n);
    }
    owner.bodies.lock().unwrap().clear();
    run_backlog(&fake, &parts, &owner, &dir.path().join("w2"), (hour_end + 200) * 1_000, 8).await.unwrap();
    assert_eq!(fake.committed(), 120, "every backlog segment is committed");

    let bodies = owner.bodies.lock().unwrap().clone();
    assert!(!bodies.is_empty());
    assert!(bodies.iter().all(|b| *b <= SIGN_REQUEST_BUDGET_BYTES && *b <= OWNER_SIGN_BODY_MAX_BYTES), "{bodies:?}");
    let uids = live_uids(&parts).await;
    assert_eq!(uids.len(), expected.len(), "no loss, no duplicates");
    assert_eq!(uids.into_iter().collect::<HashSet<_>>(), expected);

    // The test reproduces the incident: one backlog flush produced a
    // multi-hour Add whose parts, sent inline in one count-only request (the
    // stalled image), exceed the owner fence.
    let keys = LogKeys::new(TENANT).unwrap();
    let mut worst_legacy = 0;
    for seq in 0.. {
        let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { parts: refs, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            let mut inline = Vec::new();
            for part in &refs {
                let pk = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
                let signed = SignedProvenance::verify_bytes(&parts.get(&pk.provenance()).await.unwrap().unwrap(), TENANT, &signer().trusted()).unwrap();
                let canonical = signed.record.canonical_bytes().unwrap();
                inline.push(SignRequestPart {
                    part_id: signed.record.part_id.clone(),
                    record_sha256: sha256_hex(&canonical),
                    record_base64: Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &canonical)),
                    record_ref: None,
                });
            }
            // Pre-fix, a record went by reference only past 47 KiB of base64.
            let pre_fix_inline = inline.iter().all(|p| p.record_base64.as_ref().unwrap().len() <= INLINE_RECORD_MAX_BASE64);
            let legacy = SignRequest { schema_version: 1, request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(), parts: inline };
            if pre_fix_inline {
                worst_legacy = worst_legacy.max(legacy.body_bytes().unwrap());
            }
        }
    }
    assert!(worst_legacy > OWNER_SIGN_BODY_MAX_BYTES, "the backlog flush would have been refused pre-fix: {worst_legacy}");
}

async fn run_backlog(fake: &FakeDo, parts: &dyn ObjectStore, owner: &FencedOwner, work: &Path, from: i64, ticks: usize) -> Result<()> {
    run_backlog_with(fake, parts, owner, work, from, ticks, 30_000, 64).await
}

async fn run_backlog_with(fake: &FakeDo, parts: &dyn ObjectStore, owner: &FencedOwner, work: &Path, from: i64, ticks: usize, flush_ms: i64, admission: usize) -> Result<()> {
    let live = load_log(parts, TENANT).await?;
    let point = live.edge_point().or(live.edge_ended()).cloned();
    let source = Arc::new(EdgeLogSource::open(fake.clone(), TENANT, "ingest", point.as_ref(), EdgeLogSourceConfig::default()).await?);
    let queue = EdgeQueue::new(source.clone(), TENANT);
    let segments = EdgeSegments::new(source);
    let mut cfg = IngestConfig::new(TENANT, work);
    // The cell default admission width; the flush waits for the whole
    // backlog (the restart case: the age cap fires with all of it buffered).
    cfg.flush_interval_override_ms = Some(flush_ms);
    cfg.max_objects_per_admission = admission;
    let mut ingestor = Ingestor::open(cfg, parts, &segments, &queue, owner, owner.inner.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), from).await?;
    let mut clock = from;
    for _ in 0..ticks {
        ingestor.tick(clock).await?;
        clock += 11_000;
    }
    ingestor.flush_now(clock).await?;
    Ok(())
}

/// NAN-3006: a backlog larger than `MAX_FLUSH_OBJECTS` drains in several
/// flushes (each L0 record names at most that many segments), even when the
/// age cap would hold all of it, and every sign call stays under the fence.
#[tokio::test(flavor = "current_thread")]
async fn a_backlog_past_the_flush_object_cap_drains_in_bounded_flushes() {
    use nanosiem_lake_worker::part_ingest::ingest::MAX_FLUSH_OBJECTS;
    use nanosiem_lake_worker::parts::provenance::OWNER_SIGN_BODY_MAX_BYTES;
    let dir = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let fake = FakeDo::default();
    let owner = FencedOwner { inner: signer(), bodies: Mutex::new(Vec::new()) };
    let total = MAX_FLUSH_OBJECTS + 88;
    for i in 1..=total {
        let uid = format!("cap-{i:04}");
        fake.append(&backlog_seg_key(i), parquet_bytes(&[event(&uid, DAY0_S + 3_000 + (i as i64) / 4, i)]));
    }
    // No age cap in reach and the widest (bronze-mode) admission: only the
    // object cap can cut the first flush.
    run_backlog_with(&fake, &parts, &owner, &dir.path().join("w"), (DAY0_S + 3_300) * 1_000, 30, 10_000_000, 256).await.unwrap();
    assert_eq!(fake.committed(), total as u64);
    assert!(owner.bodies.lock().unwrap().iter().all(|b| *b <= OWNER_SIGN_BODY_MAX_BYTES));
    let keys = LogKeys::new(TENANT).unwrap();
    let mut adds = Vec::new();
    for seq in 0.. {
        let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            adds.push(consumed.len());
        }
    }
    assert_eq!(adds, vec![MAX_FLUSH_OBJECTS, total - MAX_FLUSH_OBJECTS], "the object cap cut the first flush");
    assert_eq!(adds.iter().sum::<usize>(), total);
    assert_eq!(live_uids(&parts).await.len(), total);
}

/// `metadata.uid` of every row of a bronze segment, in order.
fn bronze_uids(bytes: &[u8]) -> Vec<String> {
    use arrow_array::cast::AsArray;
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
        .unwrap()
        .build()
        .unwrap();
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.unwrap();
        let events = batch.column_by_name("_nano_bronze_event").unwrap().as_string::<i32>();
        for event in events.iter() {
            let event: Value = serde_json::from_str(event.unwrap()).unwrap();
            out.push(event["metadata"]["uid"].as_str().unwrap().to_string());
        }
    }
    out
}

/// One hosted landing upload, through the production path: `convert_file`
/// (the shared landing conversion running Vector's own lake storage stage),
/// `split_segments` + `segment_key` exactly as `EdgeAppend::emit` produces
/// them into the tenant edge log, then ingest[T] over that log.
fn land_hosted(fake: &FakeDo, file: &[u8], landed_at_s: i64) -> Vec<String> {
    use nanosiem_lake_worker::landing::{convert_file, FileFormat, LandingSource};
    use nanosiem_lake_worker::landing_hosted::{segment_key, split_segments, MAX_SEGMENT_BYTES};
    let stage = nanosiem_core::parsers::landing_ocsf::LandingOcsfStage::new(1).unwrap();
    let source = LandingSource {
        source_id: uuid::Uuid::parse_str("0b8f6c1e-3c55-4a8e-9d3e-2f7c1a4b5d60").unwrap(),
        route_key: "tenzir_sysmon".into(),
        credential_id: uuid::Uuid::parse_str("1b84f015-b560-433b-8bb6-ed4e39f48334").unwrap(),
        active: true,
    };
    let now = chrono::Utc::now();
    let converted = convert_file(file, FileFormat::Ndjson { gzip: false }, &stage, TENANT, &source, now).unwrap();
    assert_eq!(converted.rows_refused, 0, "{:?}", converted.first_refusal);
    let mut uids = Vec::new();
    let mut index = 0;
    for (_, body, rows) in &converted.objects {
        for (bytes, _) in split_segments(body, *rows, MAX_SEGMENT_BYTES).unwrap() {
            let key = segment_key(TENANT, &converted.content_sha256, index, Some(landed_at_s * 1_000), now);
            index += 1;
            uids.extend(bronze_uids(&bytes));
            fake.append(&key, bytes);
        }
    }
    uids
}

/// NAN-4322: the landing ledger refuses a same-key re-PUT, but the same file
/// re-uploaded under a NEW object key is a new landed file and is converted
/// again (its landing counters count it again). Its rows must not become
/// searchable twice: rows keep the sender's `metadata.uid`, rows without one
/// (or with a minted random UUIDv4) derive it from `sha256(file):ordinal`,
/// so the re-upload carries the same uids and ingest[T]'s uid window drops
/// it, whether the same consumer or a respawned one ingests the copy.
#[tokio::test(flavor = "current_thread")]
async fn the_same_landed_file_under_a_new_key_adds_zero_searchable_rows() {
    let dir = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let fake = FakeDo::default();
    let mut rows = Vec::new();
    for i in 0..40 {
        let mut row = event("placeholder", DAY0_S + 3_000 + (i as i64 % 30), i);
        let metadata = row["metadata"].as_object_mut().unwrap();
        match i % 4 {
            // The sender's own event id (Tenzir `metadata.uid` from the source).
            0 => { metadata.insert("uid".into(), json!(format!("tenzir:wks-01:{i}"))); }
            // A random UUIDv4 the sender minted (not in raw_data): replaced.
            1 => { metadata.insert("uid".into(), json!(uuid::Uuid::new_v4().to_string())); }
            // No uid at all.
            _ => { metadata.remove("uid"); }
        }
        // Tenzir rows carry no lake stamps; the stage sets them.
        metadata.remove("tenant_uid");
        metadata.remove("log_source");
        if let Some(raw) = row.get_mut("raw_data") {
            *raw = json!(format!("raw event {i}"));
        }
        rows.push(row);
    }
    // Two identical lines at different ordinals stay two real events.
    rows[39] = rows[38].clone();
    let mut file = Vec::new();
    for row in &rows {
        serde_json::to_writer(&mut file, row).unwrap();
        file.push(b'\n');
    }

    let first = land_hosted(&fake, &file, DAY0_S + 3_050);
    assert_eq!(first.len(), 40);
    assert_eq!(first.iter().collect::<HashSet<_>>().len(), 40, "every ordinal keeps its own uid");
    run_ingest(&fake, &parts, &dir.path().join("w1"), (DAY0_S + 3_100) * 1_000, 3).await.unwrap();
    assert_eq!(live_uids(&parts).await.len(), 40);

    // The sender PUTs the same bytes under a new key a minute later: the
    // ledger leases it as a new file, the converter accepts 40 rows again.
    let second = land_hosted(&fake, &file, DAY0_S + 3_110);
    assert_eq!(second, first, "a re-upload derives the same uids");
    run_ingest(&fake, &parts, &dir.path().join("w1"), (DAY0_S + 3_200) * 1_000, 3).await.unwrap();
    assert_eq!(fake.committed(), 2);
    assert_eq!(live_uids(&parts).await.len(), 40, "the re-upload adds zero searchable rows");

    // Again an hour later, ingested by a respawned consumer (fresh work dir):
    // the hour is re-hydrated from its live parts.
    land_hosted(&fake, &file, DAY0_S + 6_700);
    run_ingest(&fake, &parts, &dir.path().join("w2"), (DAY0_S + 6_800) * 1_000, 3).await.unwrap();
    assert_eq!(fake.committed(), 3);
    let uids = live_uids(&parts).await;
    assert_eq!(uids.len(), 40, "a respawned consumer drops the re-upload too");
    assert_eq!(uids.iter().collect::<HashSet<_>>(), first.iter().collect::<HashSet<_>>());

    // Control: a file that differs by one byte is other content. Only the
    // sender-uid rows (every 4th) are the same events; the 30 rows whose uid
    // the lake derived from the file are new rows, so the zero above is the
    // uid window's doing, not an artefact of the harness.
    let mut other = file.clone();
    other.push(b'\n');
    let third = land_hosted(&fake, &other, DAY0_S + 6_900);
    assert_eq!(third.iter().filter(|uid| first.contains(uid)).count(), 10);
    run_ingest(&fake, &parts, &dir.path().join("w2"), (DAY0_S + 7_000) * 1_000, 3).await.unwrap();
    assert_eq!(live_uids(&parts).await.len(), 70);
}

/// NAN-4539: the background part store with a fixed per-PUT delay, so
/// consecutive flights overlap.
struct SlowParts {
    inner: LocalObjectStore,
    in_flight: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl ObjectStore for SlowParts {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        use std::sync::atomic::Ordering;
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let written = self.inner.put_if_absent(key, bytes).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        written
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

/// NAN-4539: the production edge-source settings for the default depth
/// ([`edge_source_config`] of `MAX_FLUSH_DEPTH`, as the cell opens it) over
/// the real `EdgeLogSource`: two ranges outstanding at most, committed to the
/// DO strictly in issue order (the fake refuses a gap), each segment once,
/// with the single-flight pull allowance. A one-range source (the serial
/// contract) drains the same backlog with one flight at most.
///
/// NAN-4539 step 3a: with one range (depth 1), an age-due seal beside the
/// unfinished flight is deferred and admission keeps filling the buffer, so
/// that run drains in fewer, larger flushes (2 here, not ~20 at 8 objects
/// each); it still must never overlap two flights and must commit in order,
/// exactly once. The two-range run must still overlap several flights.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_edge_source_overlaps_two_flights_and_commits_ranges_in_order() {
    use nanosiem_lake_worker::part_ingest::ingest::{edge_source_config, MAX_FLUSH_DEPTH};
    assert_eq!(edge_source_config(MAX_FLUSH_DEPTH).max_issued_ranges, 2);
    assert_eq!(edge_source_config(MAX_FLUSH_DEPTH).max_buffered_bytes, EdgeLogSourceConfig::default().max_buffered_bytes,
        "a second range never raises the pulled-bytes allowance");
    for (source_config, max_peak, min_pipelined) in [(edge_source_config(MAX_FLUSH_DEPTH), 2, 4), (EdgeLogSourceConfig::default(), 1, 2)] {
        let dir = tempfile::tempdir().unwrap();
        let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
        let background: &'static SlowParts = Box::leak(Box::new(SlowParts {
            inner: LocalObjectStore::new(dir.path().join("parts")).unwrap(), in_flight: Default::default(), peak: Default::default(),
        }));
        let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
        let fake = FakeDo::default();
        let total = 160;
        let mut expected = HashSet::new();
        for i in 1..=total {
            let events = (0..4).map(|r| {
                let uid = format!("depth-{i:04}-{r}");
                expected.insert(uid.clone());
                event(&uid, DAY0_S + 3_000 + i as i64, i * 4 + r)
            }).collect::<Vec<_>>();
            fake.append(&backlog_seg_key(i), parquet_bytes(&events));
        }
        let source = Arc::new(EdgeLogSource::open(fake.clone(), TENANT, "ingest", None, source_config).await.unwrap());
        let queue = EdgeQueue::new(source.clone(), TENANT);
        let segments = EdgeSegments::new(source);
        let signer = signer();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("work"));
        cfg.flush_interval_override_ms = Some(10_000);
        cfg.max_objects_per_admission = 8;
        let mut ingestor = Ingestor::open(cfg, &parts, &segments, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), (DAY0_S + 3_300) * 1_000).await.unwrap();
        ingestor.set_background_store(background);
        ingestor.set_background_signer(background_signer);
        let wake = Arc::new(tokio::sync::Notify::new());
        ingestor.set_flight_wake(wake.clone());
        let mut clock = (DAY0_S + 3_300) * 1_000;
        // The widest modeled wait for the next DO commit (from the start or
        // the previous commit), to bound how long a deferred seal waits.
        let (mut last_commit, mut last_committed, mut widest_commit_wait) = (clock, 0, 0_i64);
        for _ in 0..400 {
            clock += 11_000;
            ingestor.tick(clock).await.unwrap();
            if fake.committed() != last_committed {
                widest_commit_wait = widest_commit_wait.max(clock - last_commit);
                (last_commit, last_committed) = (clock, fake.committed());
            }
            if fake.committed() == total as u64 && ingestor.health().flushes_in_flight == 0 {
                break;
            }
            let _ = tokio::time::timeout(std::time::Duration::from_millis(50), wake.notified()).await;
        }
        ingestor.flush_now(clock + 11_000).await.unwrap();
        assert_eq!(fake.committed(), total as u64, "every segment committed, ranges in order");
        let health = ingestor.health();
        let (deferred, first) = ingestor.seals_deferred();
        assert!(health.flushes_pipelined_total >= min_pipelined, "catch-up pipelined: {} (depth {max_peak}; seals deferred {deferred}, \
            sealed first {first})", health.flushes_pipelined_total);
        assert_eq!((health.seals_deferred_total, health.seals_first_total), (deferred, first), "3a's counters are in health");
        if max_peak == 1 {
            // The one-range source is where 3a defers (the modeled
            // convergence cases never do): it engaged, and a deferred seal
            // sealed by the next commit, within one 11 s tick of it.
            assert!(deferred > 0, "depth 1 deferred no age-due seal beside its flight");
            assert!(health.seal_deferred_max_ms > 0 && health.seal_deferred_max_ms <= widest_commit_wait + 11_000,
                "a deferred seal waited {} ms; the widest commit wait was {widest_commit_wait} ms", health.seal_deferred_max_ms);
        }
        assert_eq!(health.flushes_in_flight_peak, max_peak, "flights in flight at once");
        let commits = fake.0.lock().unwrap().commits.iter().map(|(through, _)| *through).collect::<Vec<_>>();
        assert!(commits.windows(2).all(|pair| pair[0] < pair[1]), "DO commits strictly in order: {commits:?}");
        let uids = live_uids(&parts).await;
        assert_eq!(uids.len(), expected.len(), "no loss, no duplicates");
        assert_eq!(uids.into_iter().collect::<HashSet<_>>(), expected);
    }
}
