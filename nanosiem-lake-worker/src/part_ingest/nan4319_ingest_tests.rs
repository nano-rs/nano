// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4319 on a real ingestor: (1) an object ingest[T] dies with (an OOM
//! SIGKILL: no error, no refusal) is refused whole and quarantined after
//! [`MAX_ADMISSION_CRASHES`] restarts instead of wedging the tenant, and the
//! objects behind it flow; (2) admission is bounded by the objects' decoded
//! size, not their compressed size (landing objects compress ~50x).

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;

const TENANT: &str = "43190000-0000-4000-8000-000000000001";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i64 = 492_096;
const CLOCK: i64 = BASE_HOUR * 3_600_000 + 600_000;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4319", ed25519_dalek::SigningKey::from_bytes(&[19; 32])).unwrap()
}

fn event(i: usize) -> Value {
    // The `nan2868_part_ingest` fixture shape (it passes bronze admission).
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64 * 7, 0).unwrap();
    let uid = format!("nan4319-{i:05}");
    let raw = format!("raw {uid} token{i}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("token logon {i}"), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
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

fn notice(key: &str, at: i64) -> SourceNotice {
    SourceNotice { tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: at }
}

#[tokio::test(flavor = "current_thread")]
async fn an_object_ingest_keeps_dying_on_is_quarantined_and_the_rest_flows() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    // Admitted rows stay buffered (unacknowledged) until a flush.
    config.flush_interval_override_ms = Some(3_600_000);
    config.prevalence_enabled = false;
    let seed = seed_schema();
    let open = || Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed, CLOCK);

    write_bronze(&root.join("sources/bronze/poison.parquet"), &(0..6).map(event).collect::<Vec<_>>());
    write_bronze(&root.join("sources/bronze/after.parquet"), &(100..104).map(event).collect::<Vec<_>>());
    spool.deliver(&notice("bronze/poison.parquet", CLOCK - 5_000)).unwrap();
    spool.deliver(&notice("bronze/after.parquet", CLOCK - 4_000)).unwrap();

    // Each process admits and dies before its flush (the OOM SIGKILL the
    // FP tenant hit every 60 s): no error, nothing refused, nothing acked.
    for restart in 0..MAX_ADMISSION_CRASHES as i64 {
        let mut ingestor = open().await.expect("ingest opens");
        let report = ingestor.tick(CLOCK + restart * 1_000).await.unwrap();
        let expected = if restart == 0 { 6 + 4 } else { 6 };
        assert_eq!(report.admitted_rows, expected, "restart {restart}: after a crash the suspect is admitted alone");
        drop(ingestor);
        assert_eq!(spool.pending(10).await.unwrap().len(), 2, "nothing acknowledged");
    }

    // The next process refuses it whole instead of admitting it again.
    let mut ingestor = open().await.expect("ingest opens");
    let report = ingestor.tick(CLOCK + 10_000).await.unwrap();
    assert_eq!(report.admitted_rows, 0);
    assert_eq!(ingestor.health().objects_admission_crashed_total, 1);
    assert_eq!(ingestor.health().objects_rejected_total, 1);
    let pending = spool.pending(10).await.unwrap();
    assert_eq!(pending.iter().map(|(_, n)| n.key.as_str()).collect::<Vec<_>>(), vec!["bronze/after.parquet"], "the poison object is acknowledged");
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.len(), 1, "kept for an operator replay");
    assert_eq!((entries[0].source_key.as_str(), entries[0].reason.as_str(), entries[0].rows_rejected),
        ("bronze/poison.parquet", "admission_invalid", 6));
    assert!(entries[0].detail.starts_with(ADMISSION_CRASHED), "{}", entries[0].detail);

    // The object behind it flows (admitted alone once: it was in flight too).
    let report = ingestor.tick(CLOCK + 11_000).await.unwrap();
    assert_eq!(report.admitted_rows, 4);
    ingestor.flush_now(CLOCK + 12_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 4);
    assert!(spool.pending(10).await.unwrap().is_empty());
    ingestor.tick(CLOCK + 13_000).await.unwrap();
    assert!(AdmissionAttempts::open(&root.join("work")).is_empty(), "acknowledged objects leave the crash ledger");
    drop(ingestor);

    // A restart with nothing in flight admits normally again.
    write_bronze(&root.join("sources/bronze/later-a.parquet"), &(200..202).map(event).collect::<Vec<_>>());
    write_bronze(&root.join("sources/bronze/later-b.parquet"), &(300..302).map(event).collect::<Vec<_>>());
    spool.deliver(&notice("bronze/later-a.parquet", CLOCK + 14_000)).unwrap();
    spool.deliver(&notice("bronze/later-b.parquet", CLOCK + 14_001)).unwrap();
    let mut ingestor = open().await.expect("ingest opens");
    assert_eq!(ingestor.tick(CLOCK + 15_000).await.unwrap().admitted_rows, 4, "both objects in one admission");
}

/// Landing objects are Vector-shaped (10k rows) but compress ~50x: the
/// compressed-size estimate (120 heap bytes per source byte) admitted 50k
/// rows into a 1.2 GB role at once. The decoded-size bound admits one such
/// object from idle on that role and leaves the next pending.
#[tokio::test(flavor = "current_thread")]
async fn admission_is_bounded_by_decoded_size_not_compressed_size() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(3_600_000);
    config.prevalence_enabled = false;
    // The FP tenant's ingest role: memory_max ~1.2 GB.
    config.buffer_budget_bytes = buffer_budget_for(1_207_787_520);

    let file = crate::landing_fixture::tenzir_auth_parquet("decoded", 20_000, CLOCK - 3_600_000);
    let source = crate::landing::LandingSource {
        source_id: uuid::Uuid::nil(), route_key: "tenzir_auth".into(), credential_id: uuid::Uuid::nil(), active: true,
    };
    let stage = nanosiem_core::parsers::landing_ocsf::LandingOcsfStage::new(1).unwrap();
    let converted = crate::landing::convert_file(&file, crate::landing::FileFormat::Parquet, &stage, TENANT, &source,
        chrono::DateTime::from_timestamp_millis(CLOCK).unwrap()).unwrap();
    assert_eq!(converted.objects.len(), 2);
    let mut compressed = 0;
    for (index, (_, body, _)) in converted.objects.iter().enumerate() {
        let key = format!("bronze/landing-{index}.parquet");
        std::fs::write(root.join("sources").join(&key), body).unwrap();
        compressed += body.len() as u64;
        spool.deliver(&SourceNotice { bytes: body.len() as u64, ..notice(&key, CLOCK - 1_000 + index as i64) }).unwrap();
    }
    // The compressed estimate alone would take both (they look small).
    let (heap, arrow) = (compressed as f64 * INITIAL_HEAP_PER_SOURCE_BYTE, compressed as f64 * INITIAL_ARROW_PER_SOURCE_BYTE);
    assert!(super::super::memory::admission_fits(config.buffer_budget_bytes, 0, heap, arrow), "{compressed} B compressed");

    let mut ingestor = Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");
    let report = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(report.admitted_rows, 10_000, "one landing object per admission on a 1.2 GB role");
    let mut now = CLOCK;
    while ingestor.health().rows_committed_total < 20_000 {
        now += 1_000;
        ingestor.tick(now).await.unwrap();
        ingestor.flush_now(now).await.unwrap();
        assert!(now < CLOCK + 20_000, "stalled: {:?}", ingestor.health());
    }
    assert!(spool.pending(10).await.unwrap().is_empty());
}
