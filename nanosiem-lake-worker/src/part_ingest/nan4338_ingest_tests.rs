// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4338 end to end on a real ingestor: an edge segment admission
//! refuses whole is quarantined AND reported to the landing ledger (its rows
//! leave the landing source's `rows`); the operator replay that commits
//! reports `replayed`; a restart reports every kept entry again; objects
//! that are not edge segments are never reported.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::quarantine_ledger::{QuarantineLedgerSink, QuarantineReport, ReportOutcome, ReportState, OUTBOX_FILE};
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;

const TENANT: &str = "43380000-0000-4000-8000-000000000001";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i64 = 492_096;

#[derive(Default)]
struct RecordingLedger(std::sync::Mutex<Vec<QuarantineReport>>);

#[async_trait::async_trait]
impl QuarantineLedgerSink for RecordingLedger {
    async fn report(&self, report: &QuarantineReport) -> anyhow::Result<ReportOutcome> {
        self.0.lock().unwrap().push(report.clone());
        Ok(ReportOutcome::Recorded)
    }
}

impl RecordingLedger {
    fn reports(&self) -> Vec<(String, u64, ReportState)> {
        self.0.lock().unwrap().iter().map(|r| (r.segment_key.clone(), r.rows, r.state)).collect()
    }
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4338", ed25519_dalek::SigningKey::from_bytes(&[38; 32])).unwrap()
}

fn event(i: usize) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64 * 7, 0).unwrap();
    let uid = format!("tzl-{i:05}");
    let raw = format!("raw {uid} token{i}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("token logon {i}"), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "tenzir_edge",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.0.{}", i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "user": {"name": format!("user{}", i % 5), "uid": format!("S-1-5-21-{}", i % 5)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": 300201
    })
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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

/// The key landing[T] produces a converted file's segment under.
fn segment_key(n: u32) -> String {
    format!("bronze-v2/shard=0/tenant_id={TENANT}/{}-00000000-0000-4000-8000-{n:012}.parquet", BASE_HOUR * 3_600)
}

struct Lab {
    _root: tempfile::TempDir,
    root: std::path::PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: LocalPartSigner,
}

impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("sources")).unwrap();
        Self {
            parts: LocalObjectStore::new(root.join("parts")).unwrap(),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), TENANT).unwrap(),
            signer: signer(),
            root,
            _root: dir,
        }
    }

    async fn ingestor(&self, clock: i64) -> Ingestor<'_> {
        let mut config = IngestConfig::new(TENANT, self.root.join("work"));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        Ingestor::open(config, &self.parts, &self.sources, &self.spool as &dyn NoticeQueue, &self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens")
    }

    fn deliver(&self, key: &str, events: &[Value], at: i64) {
        write_bronze(&self.root.join("sources").join(key), events);
        self.spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: at }).unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_quarantined_edge_segment_is_reported_and_its_replay_reverses_it() {
    let lab = Lab::new();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let ledger = Arc::new(RecordingLedger::default());
    let mut ingestor = lab.ingestor(clock).await;
    ingestor.set_quarantine_ledger(ledger.clone());

    // A healthy segment commits and is never reported.
    let healthy = segment_key(1);
    lab.deliver(&healthy, &(100..104).map(event).collect::<Vec<_>>(), clock - 5_000);
    ingestor.tick(clock - 4_000).await.unwrap();
    ingestor.flush_now(clock - 3_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 4);

    // Admission refuses a landing segment whole: kept AND reported.
    ingestor.refuse_admissions = true;
    let poison = segment_key(17);
    lab.deliver(&poison, &(0..6).map(event).collect::<Vec<_>>(), clock);
    // A refused bronze object that is not an edge segment is kept, not reported.
    lab.deliver("bronze/vector.parquet", &(200..203).map(event).collect::<Vec<_>>(), clock);
    ingestor.tick(clock + 1_000).await.unwrap();
    ingestor.flush_now(clock + 2_000).await.unwrap();
    assert_eq!(ingestor.health().objects_quarantined_total, 2);
    ingestor.settle_quarantine_ledger(clock + 2_500).await;
    assert_eq!(ledger.reports(), vec![(poison.clone(), 6, ReportState::Quarantined)]);
    assert_eq!(ingestor.quarantine_ledger().unwrap().pending(), 0);

    // The fix ships; the operator replays it and the flush commits.
    ingestor.refuse_admissions = false;
    let id = ingestor.quarantine_entries().unwrap().into_iter().find(|entry| entry.source_key == poison).unwrap().id;
    ingestor.request_quarantine_replay(TENANT, &id, clock + 3_000).unwrap();
    ingestor.tick(clock + 4_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 4 + 6);
    assert_eq!(ingestor.health().quarantine_replays_total, 1);
    ingestor.settle_quarantine_ledger(clock + 4_500).await;
    assert_eq!(ledger.reports(), vec![(poison.clone(), 6, ReportState::Quarantined), (poison, 6, ReportState::Replayed)]);
    assert_eq!(ingestor.quarantine_ledger().unwrap().recorded, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn a_restart_reports_every_kept_segment_again_and_keeps_an_unsent_outbox() {
    let lab = Lab::new();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let poison = segment_key(23);
    {
        // Kept by an ingest[T] from before NAN-4338 (no reporter installed).
        let mut ingestor = lab.ingestor(clock).await;
        ingestor.refuse_admissions = true;
        lab.deliver(&poison, &(0..5).map(event).collect::<Vec<_>>(), clock);
        ingestor.tick(clock + 1_000).await.unwrap();
        ingestor.flush_now(clock + 2_000).await.unwrap();
        assert_eq!(ingestor.health().objects_quarantined_total, 1);
    }
    // The new process reports it at start.
    let ledger = Arc::new(RecordingLedger::default());
    let mut ingestor = lab.ingestor(clock + 10_000).await;
    ingestor.set_quarantine_ledger(ledger.clone());
    assert_eq!(ingestor.quarantine_ledger().unwrap().pending(), 1);
    assert!(lab.root.join("work").join(OUTBOX_FILE).exists(), "queued durably before it is sent");
    ingestor.settle_quarantine_ledger(clock + 11_000).await;
    assert_eq!(ledger.reports(), vec![(poison, 5, ReportState::Quarantined)]);
    assert_eq!(ingestor.quarantine_ledger().unwrap().pending(), 0);
}
