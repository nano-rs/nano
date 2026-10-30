// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4770 (Mythos 1.0.12) on a real ingestor: the cell admitted one landed
//! object per flush. The fixed model predicted a 140k-row object of ~1.5 KB
//! raw events at 4.7 GiB of admission heap (16 modelled heap bytes per
//! decoded byte x 1.5 peak) against a 0.58 GiB working budget, so the
//! object was sliced only from idle: admit, seal, build, publish, commit,
//! and only then the next object.
//!
//! - Admission learns the modelled heap and Arrow bytes per decoded byte
//!   of each object prefix (bounded estimate: prior, ceiling, margin,
//!   floor), checking actual heap while reading calibrated groups.
//! - The next buffer's first object that does not fit whole is sliced
//!   beside the flights in flight when its Arrow rows and a slice fit the
//!   room they leave; otherwise it waits for them, as before (it is always
//!   admitted from idle: convergence).

use super::nan4749_ingest_tests::{event, measured, Lab, CLOCK};
use super::*;
use crate::parts::part_log::ObjectStore;
use serde_json::Value;

const MIB: u64 = 1024 * 1024;

/// Ticks until every landed row commits (at most `max_seconds`), the clock
/// advancing with the wall clock; the last buffer (never due by age under
/// the lab's hour-long flush interval) is flushed once nothing is left to
/// admit. Returns (ticks, ticks that admitted, wall seconds).
async fn drain(ingestor: &mut Ingestor<'_>, lab: &Lab, rows: u64, max_seconds: f64) -> (usize, usize, f64) {
    let started = std::time::Instant::now();
    let (mut ticks, mut admitting) = (0, 0);
    while ingestor.health().rows_committed_total < rows && started.elapsed().as_secs_f64() < max_seconds {
        let now = CLOCK + started.elapsed().as_millis() as i64;
        let report = ingestor.tick(now).await.unwrap();
        ticks += 1;
        if report.admitted_rows > 0 {
            admitting += 1;
        } else if ingestor.buffer.rows > 0 && ingestor.flush_in_flight.is_empty() && !ingestor.behind_last_tick {
            ingestor.flush_now(now).await.unwrap();
        } else if report.flushed_parts == 0 {
            // Flights build and publish on their own tasks.
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
    let health = ingestor.health();
    assert_eq!(health.rows_committed_total, rows, "every row commits once ({ticks} ticks, {admitting} admitting)");
    assert!(lab.spool.pending(1_000).await.unwrap().is_empty(), "every object acknowledged");
    (ticks, admitting, started.elapsed().as_secs_f64())
}

/// Flushes pipeline as in the cell: build and publish on their own task
/// while the next admission runs ('static handles to the lab's stores).
fn pipelined(ingestor: &mut Ingestor<'_>, lab: &Lab) {
    let parts: &'static crate::parts::part_log::LocalObjectStore =
        Box::leak(Box::new(crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap()));
    let signer: &'static crate::parts::provenance::LocalPartSigner = Box::leak(Box::new(
        crate::parts::provenance::LocalPartSigner::new("lab-signer-nan4749", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap()));
    ingestor.set_background_store(parts);
    ingestor.set_background_signer(signer);
}

fn land_objects(lab: &Lab, objects: usize, rows: usize) -> u64 {
    let mut decoded = 0;
    for object in 0..objects {
        decoded = lab.land(&format!("m{object:02}"), &(object * rows..(object + 1) * rows).map(event).collect::<Vec<_>>(), CLOCK - 5_000);
    }
    decoded
}

/// Read the published data, checking the ordering contract as well as
/// identities and payloads. Health counters alone cannot detect lost rows.
pub(super) async fn committed_rows(ingestor: &Ingestor<'_>, lab: &Lab) -> BTreeMap<String, Value> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let store = crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap();
    let live = ingestor.live_parts().into_iter().map(|part| part.part_id.to_string()).collect::<Vec<_>>();
    let mut rows = BTreeMap::new();
    let mut last_by_part = BTreeMap::new();
    for key in store.list("").await.unwrap() {
        if !key.ends_with(".parquet") || !key.contains("/data-") {
            continue;
        }
        let Some(part) = live.iter().find(|id| key.contains(id.as_str())) else { continue };
        let bytes = bytes::Bytes::from(store.get(&key).await.unwrap().unwrap());
        for batch in ParquetRecordBatchReaderBuilder::try_new(bytes).unwrap().build().unwrap() {
            let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
            writer.write(&batch.unwrap()).unwrap();
            writer.finish().unwrap();
            for line in writer.into_inner().split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
                let row: Value = serde_json::from_slice(line).unwrap();
                let uid = row["metadata"]["uid"].as_str().unwrap().to_string();
                let order = (event_time_us(&row).unwrap(), uid.clone());
                if let Some(last) = last_by_part.insert(part.clone(), order.clone()) {
                    assert!(last < order, "published rows must stay sorted across slices and data files");
                }
                assert!(rows.insert(uid, row).is_none(), "a source identity was published twice");
            }
        }
    }
    rows
}

/// A row dominated by one long raw string (an 8 KB payload).
fn long_raw(i: usize) -> Value {
    let mut event = event(i);
    let raw = format!("{i:08}").repeat(1_024);
    event["raw_data_size"] = serde_json::json!(raw.len());
    event["raw_data"] = serde_json::json!(raw);
    event
}

/// A prefix describes its writer, not a bound on its next row shape. A
/// light warm-up must not let a heavier object exceed the working budget.
#[test]
fn a_heavier_object_after_a_light_prefix_retries_with_the_fixed_reservation() {
    let lab = Lab::new(256 * MIB);
    lab.land("warmup", &(0..512).map(long_raw).collect::<Vec<_>>(), CLOCK - 5_000);
    let rows = 8_000;
    let decoded = lab.land("heavier", &(512..512 + rows).map(event).collect::<Vec<_>>(), CLOCK - 4_000);
    lab.spool.deliver(&super::super::discovery::SourceNotice {
        tenant_id: super::nan4749_ingest_tests::TENANT.into(), key: "bronze/missing.parquet".into(),
        version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: CLOCK - 4_000,
    }).unwrap();
    let (_, peak) = measured(|runtime| runtime.block_on(async {
        let mut ingestor = lab.open().await;
        let pending = lab.spool.pending(10).await.unwrap();
        let warmup = pending.iter().find(|(_, notice)| notice.key == "bronze/warmup.parquet").unwrap();
        let heavier = pending.iter().find(|(_, notice)| notice.key == "bronze/heavier.parquet").unwrap();
        let missing = pending.iter().find(|(_, notice)| notice.key == "bronze/missing.parquet").unwrap();
        assert_eq!(ingestor.admit(std::slice::from_ref(warmup), CLOCK).await.unwrap().0, 512);
        ingestor.flush_now(CLOCK + 1).await.unwrap();
        let learned = ingestor.calibration.cost("bronze", decoded);
        let fixed = decoded_admission_cost(decoded);
        let budget = ingestor.cfg.buffer_budget_bytes;
        assert!(super::super::memory::admission_fits(budget, 0, learned.0, learned.1), "fixture: history would admit the changed shape whole");
        assert!(!super::super::memory::admission_fits(budget, 0, fixed.0, fixed.1));
        let before = ingestor.health().objects_admitted_in_slices_total;
        let base = crate::test_heap::reset_peak();
        assert_eq!(ingestor.admit(&[(*missing).clone(), (*heavier).clone()], CLOCK + 2).await.unwrap().0, rows as u64);
        let peak = crate::test_heap::peak() - base;
        eprintln!("NAN-4770 shape change: learned prediction {} MiB, actual admission peak {} MiB, budget {} MiB",
            (learned.0 * super::super::memory::ADMISSION_PEAK_PER_MODELLED_HEAP + learned.1) as u64 >> 20,
            peak >> 20, budget >> 20);
        assert_eq!(ingestor.health().objects_admitted_in_slices_total, before + 1, "a heavier shape must retry with the fixed reservation and slice");
        assert!(peak < budget as isize, "the changed shape exceeded its working budget");
        assert_eq!((ingestor.health().objects_missing_total, ingestor.health().objects_rejected_total), (1, 1),
            "a refusal held before the heap retry must be recorded exactly once");
        assert_eq!(ingestor.calibration.per_decoded_byte("bronze").0, HEAP_PER_DECODED_BYTE, "the heavier observation raises the estimate immediately");
        ingestor.flush_now(CLOCK + 3).await.unwrap();
        assert_eq!(ingestor.health().rows_committed_total, rows as u64 + 512);
        assert!(lab.spool.pending(10).await.unwrap().is_empty());
    }));
    assert!(peak > 0);
}

/// NAN-4805: Mythos's 2.09 GB ingest role has a 627 MB working
/// budget. Cold estimates serialize 10k-row objects; measured rows share
/// a group, so their Arrow decode runs together on the production path.
#[test]
fn calibrated_objects_share_a_group_on_the_mythos_role() {
    let lab = Lab::new(2_090_000_000);
    let make = |i: usize| serde_json::json!({
        "time": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(CLOCK - 5_000).unwrap().to_rfc3339(),
        "class_uid": 3002, "category_uid": 3,
        "activity_id": 1, "type_uid": 300201, "severity_id": 1,
        "metadata": {"uid": format!("nan4805-{i:08}"), "tenant_uid": super::nan4749_ingest_tests::TENANT, "version": "1.9.0",
            "log_source": "WINDOWS_EVENT", "product": {"name": "fixture"}},
        "raw_data": format!("{i:08}").repeat(200), "raw_data_size": 1_600, "message": "authentication",
        "user": {"name": "fixture-user"}, "dst_endpoint": {"ip": "192.0.2.1"}
    });
    lab.land("warmup", &(0..512).map(make).collect::<Vec<_>>(), CLOCK - 5_000);
    let (_, peak) = measured(|runtime| runtime.block_on(async {
        let mut ingestor = lab.open().await;
        assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, 512);
        ingestor.flush_now(CLOCK + 1).await.unwrap();
        for object in 0..7 {
            // Fixture creation is outside the measured ingest working set.
            crate::test_heap::track_current_thread(false);
            lab.land(&format!("m{object:02}"), &(512 + object * 10_000..512 + (object + 1) * 10_000).map(make).collect::<Vec<_>>(), CLOCK - 4_000);
            crate::test_heap::track_current_thread(true);
        }
        ingestor.tick(CLOCK + 2).await.unwrap();
        assert!(ingestor.health().admission_group_objects_peak >= 2,
            "calibration still serialized the objects: {:?}", ingestor.health().admission_group_objects_peak);
        eprintln!("NAN-4805: 2.09 GB role, {} byte working budget, {} objects in one decode group",
            ingestor.cfg.buffer_budget_bytes, ingestor.health().admission_group_objects_peak);
        drain(&mut ingestor, &lab, 70_512, 120.0).await;
        let health = ingestor.health();
        assert_eq!((health.objects_consumed_total, health.objects_rejected_total, health.objects_quarantined_total), (8, 0, 0));
    }));
    assert!(peak < lab.config.buffer_budget_bytes as isize,
        "calibrated admission exceeded the working budget: {} MiB", peak >> 20);
}

/// A real local slice-write error must never turn a bounded pipelined
/// admission into an unbounded whole-object decode. The notice retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_pipelined_slice_waits_instead_of_decoding_whole() {
    let lab = Lab::new(1024 * MIB);
    let (objects, rows) = (2, 20_000);
    land_objects(&lab, objects, rows);
    let mut ingestor = lab.open().await;
    pipelined(&mut ingestor, &lab);
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, rows as u64);
    assert_eq!(ingestor.flush_in_flight.len(), 1);
    let pending = lab.spool.pending(10).await.unwrap();
    let next = pending.iter().find(|(_, notice)| notice.key == "bronze/m01.parquet").unwrap();
    let (_, sha) = super::super::writer::file_digest(&lab.root.join("sources/bronze/m01.parquet")).unwrap();
    let obstruction = lab.root.join("work/src").join(format!("{sha}.slice-00000.parquet"));
    std::fs::create_dir(&obstruction).unwrap();
    let reserved = ingestor.committed_bytes();
    let before = ingestor.health().objects_sliced_beside_flights_total;
    assert_eq!(ingestor.admit(std::slice::from_ref(next), CLOCK + 1).await.unwrap().0, 0,
        "a failed slice must wait, never decode the oversized object beside the flight");
    assert_eq!(ingestor.buffer.rows, 0);
    assert_eq!(ingestor.committed_bytes(), reserved, "the flight keeps its reservation");
    assert_eq!(ingestor.health().objects_sliced_beside_flights_total, before, "only successful slicing counts");
    assert!(ingestor.admission_deferred);
    std::fs::remove_dir(&obstruction).unwrap();
    drain(&mut ingestor, &lab, (objects * rows) as u64, 600.0).await;
    assert_eq!(ingestor.health().objects_consumed_total, objects as u64);
    assert_eq!(ingestor.health().objects_rejected_total, 0);
}

/// What the first admission teaches, measured: the blaster row shape
/// (~1 KB) models at or above the fixed 16 heap bytes per decoded byte and
/// keeps the prior; a long-string row models far below it and is learned
/// with its margin, within its bounds. Either way the measured admission
/// peak stays under what the (calibrated) model predicts.
#[test]
fn admission_learns_the_heap_per_decoded_byte_of_the_rows_it_admits() {
    let prefix = super::super::memory::calibration_prefix("bronze/probe.parquet").to_string();
    for (shape, make) in [("blaster", event as fn(usize) -> Value), ("long raw", long_raw)] {
        let lab = Lab::new(16 * 1024 * MIB);
        let rows = 4_000;
        let decoded = lab.land("probe", &(0..rows).map(make).collect::<Vec<_>>(), CLOCK - 5_000);
        let ((learned, measured_prefix), peak) = measured(|runtime| runtime.block_on(async {
            let mut ingestor = lab.open().await;
            assert_eq!(ingestor.calibration.per_decoded_byte(&prefix), (HEAP_PER_DECODED_BYTE, ARROW_PER_DECODED_BYTE), "the prior");
            assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, rows as u64);
            (ingestor.calibration.per_decoded_byte(&prefix), ingestor.calibration.measured(&prefix))
        }));
        assert!(measured_prefix);
        let (heap, arrow) = learned;
        eprintln!("NAN-4770 {shape}: {rows} rows, {} B/row decoded: predicted heap {heap:.2}/B (prior {HEAP_PER_DECODED_BYTE}), \
            arrow {arrow:.2}/B; measured tick peak {:.2}/B", decoded / rows as u64, peak as f64 / decoded as f64);
        assert!((HEAP_PER_DECODED_BYTE * super::super::memory::MIN_CALIBRATED_HEAP_SHARE..=HEAP_PER_DECODED_BYTE).contains(&heap));
        assert!(arrow <= ARROW_PER_DECODED_BYTE);
        if shape == "blaster" {
            assert_eq!(heap, HEAP_PER_DECODED_BYTE, "the 1.0.12 row shape models at the prior: no 10x headroom");
        } else {
            assert!(heap < HEAP_PER_DECODED_BYTE / 2.0, "a long-string row models far below the prior: {heap}");
        }
        // The prediction still covers what the admission really held (the
        // whole tick: parse, JSON values, Arrow decode, stamps).
        let predicted = decoded as f64 * (heap * super::super::memory::ADMISSION_PEAK_PER_MODELLED_HEAP + arrow);
        assert!((peak as f64) < predicted, "{shape}: measured {} MiB over the predicted {} MiB", peak >> 20, predicted as u64 >> 20);
    }
}

/// The bakeoff's wall on the production path, scaled down: objects that
/// the fixed model never fits beside a flight. Calibrated, the next
/// buffer's object is admitted beside the flight in flight; every row
/// still commits once, every object is acknowledged, and admission and
/// the flights together stay within one working budget.
#[test]
fn the_next_object_is_admitted_beside_the_flight_in_flight() {
    let lab = Lab::new(1024 * MIB);
    let budget = lab.config.buffer_budget_bytes;
    let (objects, rows) = (4, 20_000);
    let mut decoded = 0;
    let mut expected = BTreeMap::new();
    for object in 0..objects {
        let mut events = (object * rows..(object + 1) * rows).map(event).collect::<Vec<_>>();
        // Opposite ends of the object lie in different slices. The first
        // payload must survive a conflicting replay in the last slice.
        events[0]["message"] = serde_json::json!("first payload");
        events[rows - 1] = events[0].clone();
        events[rows - 1]["message"] = serde_json::json!("later conflicting payload");
        for row in &events[..rows - 1] {
            expected.insert(row["metadata"]["uid"].as_str().unwrap().to_string(), row["message"].clone());
        }
        decoded = lab.land(&format!("m{object:02}"), &events, CLOCK - 5_000);
    }
    let (heap, arrow) = decoded_admission_cost(decoded);
    assert!(!super::super::memory::admission_fits(budget, 0, heap, arrow), "fixture: the fixed model slices each object");
    let total = expected.len() as u64;
    let (beside, peak) = measured(|runtime| runtime.block_on(async {
        let mut ingestor = lab.open().await;
        pipelined(&mut ingestor, &lab);
        drain(&mut ingestor, &lab, total, 600.0).await;
        assert_eq!(ingestor.health().objects_consumed_total, objects as u64);
        // Test inspection materializes all published JSON. It is outside
        // the ingest working set being measured.
        crate::test_heap::track_current_thread(false);
        let actual = committed_rows(&ingestor, &lab).await;
        assert_eq!(actual.len(), expected.len());
        for (uid, message) in &expected {
            assert_eq!(&actual[uid]["message"], message, "the first payload survives for {uid}");
        }
        drop(actual);
        crate::test_heap::track_current_thread(true);
        ingestor.health().objects_sliced_beside_flights_total
    }));
    eprintln!("NAN-4770: {objects} objects x {rows} rows at a {} MiB budget: {beside} admitted beside a flight; peak {} MiB",
        budget >> 20, peak >> 20);
    assert!(beside >= 1, "no object was admitted beside a flight");
    assert!(peak < budget as isize, "peak {} MiB over {} MiB", peak >> 20, budget >> 20);
}

/// Convergence: with no room beside the flight (the budget is the flight),
/// an object waits for it and is admitted from idle, sliced; nothing is
/// refused or left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_with_no_room_beside_the_flight_waits_and_is_admitted() {
    let lab = Lab::new(256 * MIB);
    let (objects, rows) = (3, 12_000);
    land_objects(&lab, objects, rows);
    let mut ingestor = lab.open().await;
    pipelined(&mut ingestor, &lab);
    drain(&mut ingestor, &lab, (objects * rows) as u64, 600.0).await;
    let health = ingestor.health();
    assert_eq!((health.objects_consumed_total, health.objects_rejected_total, health.objects_quarantined_total), (objects as u64, 0, 0));
    assert!(health.objects_admitted_in_slices_total >= 1);
}

/// Bench (release, ignored): Mythos-shaped objects (140k rows of ~1.5 KB
/// raw events) at a 2 GiB ingest cap (the 1.0.12 bakeoff) and at the
/// shared 6 GiB full-flush sizing (#8265), the fixed model vs calibrated.
/// cargo test --release -p nanosiem-lake-worker --lib nan4770_admission_bench -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn nan4770_admission_bench() {
    // A simulated 8-core host: the decode / row-work pool at 8 threads.
    let _ = rayon::ThreadPoolBuilder::new().num_threads(8).build_global();
    eprintln!("NAN-4770 bench: rayon {} threads, tokio 8 workers, host parallelism {:?}", rayon::current_num_threads(), std::thread::available_parallelism());
    let (objects, rows) = (4, 140_000);
    for cap_gib in [2, 6] {
    let mut results = Vec::new();
    for fixed in [true, false] {
        let lab = Lab::new(cap_gib * 1024 * MIB);
        let decoded = land_objects(&lab, objects, rows);
        let mut ingestor = lab.open().await;
        pipelined(&mut ingestor, &lab);
        ingestor.fixed_admission_model = fixed;
        let total = (objects * rows) as u64;
        let (ticks, admitting, seconds) = drain(&mut ingestor, &lab, total, 3_600.0).await;
        let health = ingestor.health();
        let line = format!("{cap_gib} GiB cap, {}: {objects} x {rows} rows ({} MiB decoded each), budget {} MiB: {seconds:.1} s, {:.0} eps, \
            {ticks} ticks, {admitting} admitting ({:.2} objects/admitting tick), sliced {} (beside flights {}), learned heap {:.2}/B arrow {:.2}/B",
            if fixed { "fixed model" } else { "calibrated" }, decoded >> 20, lab.config.buffer_budget_bytes >> 20,
            total as f64 / seconds, objects as f64 / admitting.max(1) as f64, health.objects_admitted_in_slices_total,
            health.objects_sliced_beside_flights_total,
            ingestor.calibration.per_decoded_byte("bronze").0, ingestor.calibration.per_decoded_byte("bronze").1);
        eprintln!("NAN-4770 bench {line}");
        results.push(total as f64 / seconds);
    }
    eprintln!("NAN-4770 bench {cap_gib} GiB cap: calibrated / fixed eps = {:.2}x", results[1] / results[0]);
    }
}
