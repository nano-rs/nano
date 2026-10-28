// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4765 (NAN-4689 v3 soak): commit eps fell from 12.5k to 7.4k within an
//! hour while the uid window grew to 21.8M uids in the current hour. On the
//! production path (`Ingestor::open` with its local prevalence state,
//! `tick`), the per-row cost of the uid-window walk and of the prevalence
//! stamp does not grow with the window: admitting the same rows costs the
//! same next to a small window and next to one holding 20M+ uids.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;

const TENANT: &str = "47650000-0000-4000-8000-000000000001";
const DAY0_S: i64 = 1_790_294_400;
const OBJECTS: usize = 8;
const ROWS: usize = 1_000;
/// Uids held next to the second phase's admissions: past the soak's 21.8M.
const PREFILL_UIDS: usize = 22_000_000;

/// A soak-like row: its own uid and its own artifacts (prevalence keys).
fn event(phase: usize, object: usize, row: usize, time_s: i64) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(time_s, 0).unwrap();
    let n = (phase * OBJECTS + object) * ROWS + row;
    let uid = format!("nan4765-{n:08}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", row % 50)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("logon {uid}"), "raw_data": format!("raw {uid}"), "raw_data_size": uid.len() + 4,
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.{}.{}.{}", n / 65_536 % 256, n / 256 % 256, n % 256), "hostname": format!("ws-{}.corp.local", n % 97)},
        "dst_endpoint": {"ip": format!("8.{}.{}.{}", n / 65_536 % 256, n / 256 % 256, n % 256)},
        "user": {"name": format!("user{}", row % 50), "uid": format!("S-1-5-21-{}", row % 50)},
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

/// Land one phase's objects (all in the first hour of `DAY0_S`).
fn land(root: &std::path::Path, spool: &SpoolQueue, phase: usize) {
    for object in 0..OBJECTS {
        let at = DAY0_S + 600 + (phase * OBJECTS + object) as i64 * 20;
        let events = (0..ROWS).map(|row| event(phase, object, row, at - 5)).collect::<Vec<_>>();
        let key = format!("bronze/{at}-{phase}-{object:03}.parquet");
        write_bronze(&root.join("sources").join(&key), &events);
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: at * 1_000 }).unwrap();
    }
}

/// Total elapsed µs of one operation timing.
fn elapsed_us(ingestor: &Ingestor<'_>, operation: &str) -> u64 {
    ingestor.diagnostics.operations.snapshot()[operation]["elapsed_us_total"].as_u64().unwrap_or(0)
}

/// Rows in committed parts.
fn committed(ingestor: &Ingestor<'_>) -> u64 {
    ingestor.log.live().parts().map(|part| part.rows).sum::<u64>()
}

/// Tick until the phase is admitted, committed and applied; per-row µs of
/// the uid-window walk and of the stamp lookups it took.
async fn phase_cost(ingestor: &mut Ingestor<'_>, spool: &SpoolQueue, clock: &mut i64, phase: usize) -> (f64, f64) {
    let (dedupe0, stamp0) = (elapsed_us(ingestor, "admission_dedupe"), elapsed_us(ingestor, "stamp_lookup"));
    let wanted = ((phase + 1) * OBJECTS * ROWS) as u64;
    for _ in 0..400 {
        *clock += 11_000;
        ingestor.tick(*clock).await.unwrap();
        let idle = committed(ingestor) == wanted && spool.pending(1).await.unwrap().is_empty()
            && ingestor.health().buffered_rows == 0 && ingestor.health().flushes_in_flight == 0;
        if idle && !ingestor.prevalence_pending() && ingestor.prevalence_status() == "stamping" {
            let rows = (OBJECTS * ROWS) as f64;
            return ((elapsed_us(ingestor, "admission_dedupe") - dedupe0) as f64 / rows,
                (elapsed_us(ingestor, "stamp_lookup") - stamp0) as f64 / rows);
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("ingest did not drain: committed {} of {wanted}, pending notices {}, prevalence {}, health {}",
        committed(ingestor), spool.pending(100).await.unwrap().len(), ingestor.prevalence_status(),
        serde_json::to_string(ingestor.health()).unwrap());
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "NAN-4765 scale proof: holds a 22M-uid window (~2 GB resident); run with --ignored"]
async fn per_row_dedupe_and_stamp_cost_stay_flat_from_a_small_window_to_22m_uids() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer: &'static LocalPartSigner = Box::leak(Box::new(
        LocalPartSigner::new("lab-signer-nan4765", ed25519_dalek::SigningKey::from_bytes(&[65; 32])).unwrap()));
    let background: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.join("parts")).unwrap()));
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(10_000);
    // The soak's current hour (21.8M uids) was buffered, so the cap never
    // evicted it; hold the prefilled hour the same way between flushes.
    config.max_window_uids = 2 * PREFILL_UIDS;
    let mut clock = (DAY0_S + 600) * 1_000;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    ingestor.set_background_store(background);
    ingestor.set_background_signer(signer);
    // Warm-up phase (opens, first stamps, first flush), then the measured
    // phase next to a small window.
    land(&root, &spool, 0);
    phase_cost(&mut ingestor, &spool, &mut clock, 0).await;
    land(&root, &spool, 1);
    let small_window = ingestor.window.len();
    let (small_dedupe, small_stamp) = phase_cost(&mut ingestor, &spool, &mut clock, 1).await;
    // The same hour now holds 22M more uids (random 128-bit keys, as the
    // keyed uid hash yields).
    let hour = event_hour_of(DAY0_S * 1_000_000);
    let mut seed = 4765_u64;
    for _ in 0..PREFILL_UIDS {
        let key = super::super::dedup::UidKey([splitmix(&mut seed), splitmix(&mut seed)]);
        ingestor.window.observe_key(hour, key, 1, clock);
    }
    land(&root, &spool, 2);
    let large_window = ingestor.window.len();
    let (large_dedupe, large_stamp) = phase_cost(&mut ingestor, &spool, &mut clock, 2).await;
    eprintln!("NAN-4765 per-row µs (window uids: dedupe, stamp): small {small_window}: {small_dedupe:.2}, {small_stamp:.2}; \
        large {large_window}: {large_dedupe:.2}, {large_stamp:.2}");
    assert!(large_window >= PREFILL_UIDS, "the window held the prefill: {large_window}");
    assert_eq!(ingestor.window.len(), large_window + OBJECTS * ROWS, "every measured row was new and kept in the window");
    assert!(large_dedupe <= small_dedupe * 1.10 + 0.5,
        "per-row window cost stays flat: {small_dedupe:.2} µs at {small_window} uids, {large_dedupe:.2} µs at {large_window}");
    assert!(large_stamp <= small_stamp * 1.10 + 2.0,
        "per-row stamp cost does not follow the window: {small_stamp:.2} µs, then {large_stamp:.2} µs");
    assert_eq!(committed(&ingestor), (3 * OBJECTS * ROWS) as u64, "every row committed once");
}
