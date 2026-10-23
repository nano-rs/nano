// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3643 end to end on a real ingestor: an object admission refuses whole
//! is quarantined with its reason, survives as long as its TTL, and an
//! operator replay after the cause is fixed admits it exactly once through
//! normal admission (uid dedupe included); another tenant cannot replay it.

use super::*;
use serde_json::json;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::quarantine::ReplayRefused;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;

const TENANT: &str = "36430000-0000-4000-8000-000000000001";
const OTHER: &str = "36430000-0000-4000-8000-000000000002";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i64 = 492_096;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3643", ed25519_dalek::SigningKey::from_bytes(&[43; 32])).unwrap()
}

fn event(i: usize) -> Value {
    // The `nan2868_part_ingest` fixture shape (it passes bronze admission).
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64 * 7, 0).unwrap();
    let uid = format!("gws-{i:05}");
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

#[tokio::test(flavor = "current_thread")]
async fn refused_object_is_quarantined_then_replayed_once_after_the_fix() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    config.prevalence_enabled = false;
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    let events = (0..6).map(event).collect::<Vec<_>>();
    let deliver = |name: &str, at: i64| {
        let key = format!("bronze/{name}.parquet");
        write_bronze(&root.join("sources").join(&key), &events);
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: at }).unwrap();
    };

    // Control: the fixture rows pass admission.
    let control = (100..102).map(event).collect::<Vec<_>>();
    write_bronze(&root.join("sources").join("bronze/control.parquet"), &control);
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/control.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock - 5_000 }).unwrap();
    ingestor.tick(clock - 4_000).await.unwrap();
    ingestor.flush_now(clock - 3_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2, "control rows commit: {:?}", ingestor.quarantine_entries().unwrap());

    // An admission bug refuses the whole object: refused, acked, quarantined.
    ingestor.refuse_admissions = true;
    deliver("gws", clock);
    ingestor.tick(clock + 1_000).await.unwrap();
    ingestor.flush_now(clock + 2_000).await.unwrap();
    assert!(spool.pending(10).await.unwrap().is_empty(), "the refused notice is acknowledged");
    assert_eq!(ingestor.health().objects_rejected_total, 1);
    assert_eq!(ingestor.health().objects_quarantined_total, 1);
    assert_eq!(ingestor.health().rows_committed_total, 2);
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = entries[0].clone();
    assert_eq!((entry.tenant_id.as_str(), entry.source_key.as_str(), entry.scope.as_str()), (TENANT, "bronze/gws.parquet", "object"));
    assert_eq!((entry.reason.as_str(), entry.rows_rejected), ("admission_invalid", 6));
    assert!(entry.detail.contains("simulated admission bug"), "{}", entry.detail);

    // A replay requested while the bug is live is refused again and stays.
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 3_000).unwrap();
    ingestor.tick(clock + 4_000).await.unwrap();
    let still = ingestor.quarantine_entries().unwrap();
    assert_eq!(still.len(), 1);
    assert_eq!((still[0].refusals, still[0].replay_requested_at_ms), (2, None), "refused again, request cleared");
    assert_eq!(ingestor.health().rows_committed_total, 2);
    ingestor.tick(clock + 5_000).await.unwrap();
    assert_eq!(ingestor.quarantine_entries().unwrap()[0].refusals, 2, "a cleared request is not retried");

    // Another tenant can never replay it.
    let cross = ingestor.request_quarantine_replay(OTHER, &entry.id, clock + 5_000).unwrap_err();
    assert_eq!(cross.downcast_ref::<ReplayRefused>(), Some(&ReplayRefused::CrossTenant));

    // The fix ships: the replay is admitted once and leaves the quarantine.
    ingestor.refuse_admissions = false;
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 6_000).unwrap();
    ingestor.tick(clock + 7_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2 + 6, "every refused row is committed: {:?} {:?}",
        ingestor.quarantine_entries().unwrap(), ingestor.health());
    assert_eq!(ingestor.health().quarantine_replays_total, 1);
    assert!(ingestor.quarantine_entries().unwrap().is_empty());
    let again = ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 8_000).unwrap_err();
    assert_eq!(again.downcast_ref::<ReplayRefused>(), Some(&ReplayRefused::NotFound), "a committed replay cannot run twice");
    let consumed = ingestor.log.live().consumed(&SourceRef {
        key: super::super::quarantine::quarantine_replay_key(TENANT, &entry.id),
        version: QUARANTINE_REPLAY_VERSION.into(),
        sha256: entry.id.clone(),
    });
    assert!(consumed, "the replay is a consumed source in the part log");

    // The source re-sends the same events later: uid dedupe drops them all.
    deliver("gws-resent", clock + 9_000);
    ingestor.tick(clock + 10_000).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2 + 6, "no duplicates after a replay");
    assert!(spool.pending(10).await.unwrap().is_empty());
}
