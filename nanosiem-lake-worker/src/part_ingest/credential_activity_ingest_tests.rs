// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3899 end to end on a real ingestor: committed rows are attributed to
//! the credential the edge stamped, an unused credential is never listed, a
//! crash replay is not counted twice, and two tenants' cells never write
//! into each other's snapshot.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use std::sync::Mutex;

const TENANT: &str = "38990000-0000-4000-8000-000000000001";
const OTHER: &str = "38990000-0000-4000-8000-000000000002";
/// The tenant's two HEC loadgen credentials; only `HEC_A` sends.
const HEC_A: &str = "38990000-aaaa-4000-8000-000000000001";
const HEC_B: &str = "38990000-bbbb-4000-8000-000000000002";
/// The other tenant's credential.
const OTHER_HEC: &str = "38990000-cccc-4000-8000-000000000003";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i64 = 492_096;
const HOUR: i64 = 3_600_000;

#[derive(Default)]
struct Recorder(Mutex<Vec<Value>>);

#[async_trait::async_trait]
impl ActivitySink for Recorder {
    async fn record(&self, snapshot: Value) -> Result<i32> {
        self.0.lock().unwrap().push(snapshot);
        Ok(1)
    }
}

impl Recorder {
    fn last(&self) -> Option<Value> {
        self.0.lock().unwrap().last().cloned()
    }
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3899", ed25519_dalek::SigningKey::from_bytes(&[99; 32])).unwrap()
}

fn event(tenant: &str, i: usize, credential: Option<&str>) -> Value {
    let time = chrono::DateTime::<Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64 * 7, 0).unwrap();
    let mut metadata = json!({"uid": format!("{tenant}-{i:05}"), "version": "1.9.0", "log_name": "security",
        "log_source": "windows_security", "tenant_uid": tenant,
        "product": {"name": "fixture", "vendor_name": "nano"}});
    if let Some(credential) = credential {
        metadata["nano_credential_id"] = json!(credential);
    }
    json!({
        "time": time.to_rfc3339(), "class_uid": 3002, "class_name": "Authentication", "category_uid": 3,
        "category_name": "Identity & Access Management", "activity_id": 1, "activity_name": "Logon", "type_uid": 300201,
        "severity": "Informational", "severity_id": 1,
        "user": {"name": format!("user{i}"), "uid": format!("S-1-5-21-{i}")},
        // Bronze admission refused every row of the bare shape (strict OCSF
        // constraints); this is the `nan2868_part_ingest` shape that passes.
        "src_endpoint": {"ip": format!("10.0.0.{}", i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "message": format!("logon {i}"), "raw_data": format!("raw logon {i:05}"), "raw_data_size": 15, "status": "Success", "status_id": 1, "metadata": metadata,
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

struct Cell {
    root: std::path::PathBuf,
    tenant: &'static str,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: LocalPartSigner,
}

impl Cell {
    fn new(root: &std::path::Path, tenant: &'static str) -> Self {
        let root = root.join(tenant);
        std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
        Self {
            parts: LocalObjectStore::new(root.join("parts")).unwrap(),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), tenant).unwrap(),
            signer: signer(),
            root,
            tenant,
        }
    }

    async fn ingestor(&self, sink: Arc<Recorder>, clock: i64) -> Ingestor<'_> {
        let mut config = IngestConfig::new(self.tenant, self.root.join("work"));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(config, &self.parts, &self.sources, &self.spool as &dyn NoticeQueue, &self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
        ingestor.set_credential_activity(ActivityExec::fixed(self.tenant, sink));
        ingestor
    }

    /// Deliver `events` as one bronze object `name` and commit it.
    async fn deliver(&self, ingestor: &mut Ingestor<'_>, name: &str, events: &[Value], clock: i64) -> u64 {
        let key = format!("bronze/{name}.parquet");
        write_bronze(&self.root.join("sources").join(&key), events);
        self.spool.deliver(&SourceNotice { tenant_id: self.tenant.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: clock }).unwrap();
        let report = ingestor.tick(clock + 1_000).await.expect("admit");
        ingestor.flush_now(clock + 2_000).await.expect("flush");
        report.admitted_rows
    }
}

/// Tick until the snapshot written is the one wanted (the write runs off
/// the tick). The delivery's own tick already scheduled the next write a
/// [`FLUSH_INTERVAL_MS`] out, so tick past it: before that nothing is due.
async fn written(ingestor: &mut Ingestor<'_>, sink: &Recorder, at: i64) -> Value {
    ingestor.tick(at + FLUSH_INTERVAL_MS).await.expect("tick");
    for _ in 0..200 {
        if let Some(snapshot) = sink.last() {
            return snapshot;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no credential activity was written");
}

fn listed<'v>(snapshot: &'v Value, credential: &str) -> Option<&'v Value> {
    snapshot["credentials"].as_array().unwrap().iter().find(|c| c["credential_id"] == credential)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_rows_are_attributed_to_the_sending_token_once() {
    let dir = tempfile::tempdir().unwrap();
    let cell = Cell::new(dir.path(), TENANT);
    let sink = Arc::new(Recorder::default());
    let mut clock = (BASE_HOUR + 1) * HOUR;
    let mut ingestor = cell.ingestor(sink.clone(), clock).await;

    // Four rows from HEC_A, two the edge did not attribute; HEC_B sends nothing.
    let events = (0..6).map(|i| event(TENANT, i, (i < 4).then_some(HEC_A))).collect::<Vec<_>>();
    assert_eq!(cell.deliver(&mut ingestor, "first", &events, clock).await, 6);
    clock += 10_000;
    let snapshot = written(&mut ingestor, &sink, clock).await;
    assert_eq!(snapshot["tenant_uuid"], TENANT);
    let a = listed(&snapshot, HEC_A).expect("the sending token is listed");
    assert_eq!(a["events_24h"], 4, "only the rows stamped with its id");
    assert!(a["bytes_24h"].as_u64().unwrap() > 0);
    assert!(a["last_accepted_at"].is_string());
    assert!(listed(&snapshot, HEC_B).is_none(), "an unused token is never listed: it stays waiting");
    assert_eq!(snapshot["credentials"].as_array().unwrap().len(), 1, "unattributed rows are no credential");

    // A crash replay of the same object is all duplicates: not counted again.
    let notice = SourceNotice { tenant_id: TENANT.into(), key: "bronze/first.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock };
    cell.spool.deliver(&notice).unwrap();
    ingestor.tick(clock + 1_000).await.expect("replay");
    ingestor.flush_now(clock + 2_000).await.expect("flush");
    let activity = ingestor.credential_activity().expect("kept");
    assert_eq!(listed(&activity.snapshot(clock + 3_000), HEC_A).unwrap()["events_24h"], 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_tenants_never_write_into_each_others_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let clock = (BASE_HOUR + 1) * HOUR;
    let (mine, theirs) = (Cell::new(dir.path(), TENANT), Cell::new(dir.path(), OTHER));
    let (my_sink, their_sink) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    let mut my_ingestor = mine.ingestor(my_sink.clone(), clock).await;
    let mut their_ingestor = theirs.ingestor(their_sink.clone(), clock).await;

    let my_events = (0..3).map(|i| event(TENANT, i, Some(HEC_A))).collect::<Vec<_>>();
    let their_events = (0..5).map(|i| event(OTHER, i, Some(OTHER_HEC))).collect::<Vec<_>>();
    mine.deliver(&mut my_ingestor, "mine", &my_events, clock).await;
    theirs.deliver(&mut their_ingestor, "theirs", &their_events, clock).await;

    let my_snapshot = written(&mut my_ingestor, &my_sink, clock + 10_000).await;
    let their_snapshot = written(&mut their_ingestor, &their_sink, clock + 10_000).await;
    assert_eq!(my_snapshot["tenant_uuid"], TENANT);
    assert_eq!(their_snapshot["tenant_uuid"], OTHER);
    assert_eq!(listed(&my_snapshot, HEC_A).unwrap()["events_24h"], 3);
    assert!(listed(&my_snapshot, OTHER_HEC).is_none(), "another tenant's credential never reaches this snapshot");
    assert_eq!(listed(&their_snapshot, OTHER_HEC).unwrap()["events_24h"], 5);
    assert!(listed(&their_snapshot, HEC_A).is_none());
}
