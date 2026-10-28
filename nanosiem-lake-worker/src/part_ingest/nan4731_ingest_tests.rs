// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4731 (NAN-4689 soak): a pipelined catch-up seal wakes the cell loop
//! at once. The soak's seals came from a deferred object
//! (`admission_deferred`), which skips the "more notices" wake, and the
//! flight wakes the loop only once published (~2 s): the loop idled on its
//! 1 s timer once per flush with notices waiting.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::time::Duration;

const TENANT: &str = "47310000-0000-4000-8000-000000000001";
const BASE_HOUR: i64 = 492_096;
const CLOCK: i64 = BASE_HOUR * 3_600_000 + 600_000;
/// The cell sizes the working budget from the role's memory cap; this cap
/// gives the 64 MiB floor budget.
const MEMORY_CAP: u64 = 200 * 1024 * 1024;

fn event(i: usize) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64, 0).unwrap();
    let uid = format!("nan4731-{i:06}");
    // Wide rows: one object alone does not fit the 64 MiB budget's
    // modelled admission peak, so the second object is deferred.
    let raw = format!("raw {uid} token{i}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("token logon {i} {}", "x".repeat(2_048 + i % 7)), "raw_data": raw, "raw_data_size": raw.len(),
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

/// The flight's publication never finishes, so only ingest itself can
/// leave a wake permit.
struct NeverPublishes;
#[async_trait::async_trait]
impl ObjectStore for NeverPublishes {
    async fn get(&self, _: &str) -> Result<Option<Vec<u8>>> { std::future::pending().await }
    async fn put_if_absent(&self, _: &str, _: &[u8]) -> Result<bool> { std::future::pending().await }
    async fn put(&self, _: &str, _: &[u8]) -> Result<()> { std::future::pending().await }
    async fn delete(&self, _: &str) -> Result<()> { std::future::pending().await }
    async fn list(&self, _: &str) -> Result<Vec<String>> { std::future::pending().await }
}

async fn permit(wake: &tokio::sync::Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(200), wake.notified()).await.is_ok()
}

#[tokio::test]
async fn a_pipelined_seal_behind_wakes_the_loop_for_the_next_admission() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.join("parts")).unwrap()));
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    // The landing / spool queues allow one outstanding range: depth 1, as on
    // the NAN-4689 soak.
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer: &'static LocalPartSigner = Box::leak(Box::new(
        LocalPartSigner::new("lab-signer-nan4731", ed25519_dalek::SigningKey::from_bytes(&[31; 32])).unwrap()));
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.prevalence_enabled = false;
    // The cell's sizing (part_ingest/cell.rs).
    size_for_memory_cap(&mut config, MEMORY_CAP);
    assert_eq!(config.buffer_budget_bytes, 64 * 1024 * 1024);
    let seed = seed_schema();
    let mut ingestor = Ingestor::open(config, parts, &sources, &spool as &dyn NoticeQueue, signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed, CLOCK).await.expect("ingest opens");
    ingestor.set_background_store(Box::leak(Box::new(NeverPublishes)));
    ingestor.set_background_signer(signer);
    let wake = Arc::new(tokio::sync::Notify::new());
    ingestor.set_flight_wake(wake.clone());

    for (index, name) in ["a", "b", "c"].iter().enumerate() {
        let start = index * 1_500;
        write_bronze(&root.join(format!("sources/bronze/{name}.parquet")),
            &(start..start + 1_500).map(event).collect::<Vec<_>>());
        spool.deliver(&notice(&format!("bronze/{name}.parquet"), CLOCK - 5_000 + index as i64)).unwrap();
    }

    // One tick: the first object is admitted, the second does not fit the
    // budget even alone (deferred), so the buffer seals and pipelines with
    // two notices still waiting.
    let report = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(report.admitted_rows, 1_500, "the first object only");
    assert_eq!(ingestor.health().flushes_pipelined_total, 1, "the buffer sealed into a background flight");
    assert_eq!(ingestor.health().flushes_in_flight, 1, "its publication never finishes here");
    assert!(permit(&wake).await, "notices are waiting beside an empty buffer: the loop must not idle for its timer");
    assert!(!permit(&wake).await, "one wake per seal, no spin");

    // Steady state behind with the flight still out (depth 1): the woken
    // tick admits nothing that does not fit and seals nothing, so it must
    // leave no permit; a wake on "behind" alone would spin the loop for
    // the whole publication.
    let report = tokio::time::timeout(Duration::from_secs(30), ingestor.tick(CLOCK + 10))
        .await.expect("a tick beside an unfinished flight never waits for it").unwrap();
    assert_eq!(report.admitted_rows, 0, "the next object still does not fit beside the flight");
    assert_eq!(ingestor.health().flushes_pipelined_total, 1, "nothing else sealed");
    assert!(!permit(&wake).await, "behind with nothing sealed: no wake, the loop waits for the flight or its timer");
}
