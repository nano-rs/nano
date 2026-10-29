// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4749 on a real ingestor (the 1.0.11 bakeoff, wall #1): admission is
//! the cell's limiter at 10k eps.
//!
//! - One tick admits several groups decoded one after another, each within
//!   the working budget beside the Arrow rows of the groups before it, so a
//!   tick is no longer capped by one group's transient JSON peak.
//! - The per-row work after the decode (risk-field strip, prevalence stamp,
//!   event time, uid window keys) runs in rayon chunks like the decode; the
//!   committed rows, refusals and acknowledgements are exactly the serial ones.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;

pub(super) const TENANT: &str = "47490000-0000-4000-8000-000000000001";
pub(super) const BASE_HOUR: i64 = 492_096;
pub(super) const CLOCK: i64 = BASE_HOUR * 3_600_000 + 600_000;

/// The NAN-4553 raw-log-blaster row shape (a ~1.5 KB raw event).
pub(super) fn event(i: usize) -> Value {
    let fat = 1;
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + (i as i64 % 3_000), 0).unwrap();
    let uid = format!("nan4749-{i:06}");
    let h = |k: u64| format!("{:016x}", ((i % 1500) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(k).rotate_left(17));
    let raw = format!("<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><Computer>ws-{}.corp.local</Computer></System><EventData><Data Name='UtcTime'>{}</Data><Data Name='ProcessGuid'>{{{}-{}}}</Data><Data Name='ProcessId'>{}</Data><Data Name='Image'>C:\\Windows\\System32\\{}.exe</Data><Data Name='CommandLine'>{}.exe /c {} {} {}</Data><Data Name='CurrentDirectory'>C:\\Users\\user{}\\</Data><Data Name='User'>CORP\\user{}</Data><Data Name='Hashes'>SHA256={}{}{}{},MD5={}{}</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentCommandLine'>explorer.exe {}</Data></EventData></Event>",
        i % 97, time.to_rfc3339(), h(1), h(2), i % 65_000, h(3), h(4), h(5), h(6), h(7), i % 50, i % 50, h(8), h(9), h(10), h(11), h(12), h(13), h(14));
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 50)},
            "process": {"name": "lsass.exe", "pid": 600 + i % 30, "cmd_line": format!("lsass.exe {}", h(14))}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("logon via {}.exe", h(3)), "raw_data": raw.repeat(fat), "raw_data_size": raw.len() * fat,
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 250), "hostname": format!("ws-{}.corp.local", i % 97)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20), "hostname": format!("dc-{}.corp.local", i % 3)},
        "user": {"name": format!("user{}", i % 50), "uid": format!("S-1-5-21-{}", i % 50), "domain": "CORP"},
        "unmapped": {"process_guid": h(1), "image": format!("C:\\Windows\\System32\\{}.exe", h(3)), "command_line": format!("{}.exe /c {} {} {}", h(4), h(5), h(6), h(7)),
            "hashes": format!("SHA256={}{}{}{}", h(8), h(9), h(10), h(11)), "parent_image": "C:\\Windows\\explorer.exe", "logon_id": h(12)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": 300201
    })
}

pub(super) fn write_bronze(path: &std::path::Path, events: &[Value]) {
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

pub(super) struct Lab {
    _root: tempfile::TempDir,
    pub(super) root: std::path::PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    pub(super) spool: SpoolQueue,
    signer: LocalPartSigner,
    pub(super) config: IngestConfig,
}

impl Lab {
    /// An ingest[T] sized from `memory_cap` the way the cell sizes it.
    pub(super) fn new(memory_cap: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
        let mut config = IngestConfig::new(TENANT, root.join("work"));
        // Admitted rows stay buffered (unacknowledged) until a flush.
        config.flush_interval_override_ms = Some(3_600_000);
        config.prevalence_enabled = false;
        size_for_memory_cap(&mut config, memory_cap);
        Self {
            parts: LocalObjectStore::new(root.join("parts")).unwrap(),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), TENANT).unwrap(),
            signer: LocalPartSigner::new("lab-signer-nan4749", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap(),
            config,
            _root: dir,
            root,
        }
    }

    pub(super) fn land(&self, name: &str, events: &[Value], at: i64) -> u64 {
        let key = format!("bronze/{name}.parquet");
        let path = self.root.join("sources").join(&key);
        write_bronze(&path, events);
        self.spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: at }).unwrap();
        crate::bronze::bronze_file_decoded_bytes(&path).unwrap()
    }

    pub(super) async fn open(&self) -> Ingestor<'_> {
        Ingestor::open(self.config.clone(), &self.parts, &self.sources, &self.spool as &dyn NoticeQueue, &self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens")
    }
}

/// Heap high-water mark of `work`, counting this thread, the Tokio blocking
/// pool and a private rayon pool (as `nan4553_ingest_tests::measured`).
pub(super) fn measured<T: Send>(work: impl FnOnce(&tokio::runtime::Runtime) -> T + Send) -> (T, isize) {
    let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4)
        .start_handler(|_| crate::test_heap::track_current_thread(true)).build().unwrap();
    pool.install(|| {
        crate::test_heap::track_current_thread(true);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
            .on_thread_start(|| crate::test_heap::track_current_thread(true)).build().unwrap();
        let base = crate::test_heap::reset_peak();
        let out = work(&runtime);
        let peak = crate::test_heap::peak() - base;
        crate::test_heap::track_current_thread(false);
        (out, peak)
    })
}

/// The bakeoff's per-tick cap: objects that fit the working budget only a
/// few at a time (their JSON values) used to take one tick per group. One
/// tick now admits every one of them in groups, every row commits once,
/// every object is acknowledged, and the admission heap stays within the
/// same bound a single group had.
#[test]
fn one_tick_admits_several_groups_within_the_budget() {
    // A 256 MiB ingest cap: a 76.8 MiB working budget.
    let lab = Lab::new(256 * 1024 * 1024);
    let budget = lab.config.buffer_budget_bytes;
    // Several objects per group, with all 12 objects' Arrow rows fitting
    // the smaller buffer cap beside reserved merge/admission headroom.
    let probe = lab.root.join("probe.parquet");
    write_bronze(&probe, &(0..400).map(event).collect::<Vec<_>>());
    let per_row = crate::bronze::bronze_file_decoded_bytes(&probe).unwrap() as f64 / 400.0;
    let (heap_row, arrow_row) = decoded_admission_cost(per_row as u64);
    let objects = 12;
    let rows = (budget as f64 / (4.5 * (heap_row * 1.5 + arrow_row))) as usize;
    let mut decoded = 0;
    for object in 0..objects {
        decoded = lab.land(&format!("o{object:02}"), &(object * rows..(object + 1) * rows).map(event).collect::<Vec<_>>(), CLOCK - 5_000);
    }
    let (heap, arrow) = decoded_admission_cost(decoded);
    // How many such objects one group (the old per-tick bound) admits.
    let single = (1..=objects).take_while(|n| super::super::memory::admission_fits(budget, 0, heap * *n as f64, arrow * *n as f64)).count();
    assert!((1..objects / 2).contains(&single), "fixture: one group holds {single} of {objects} objects");
    let total = (objects * rows) as u64;
    let (_, peak) = measured(|runtime| runtime.block_on(async {
        let mut ingestor = lab.open().await;
        let report = ingestor.tick(CLOCK).await.unwrap();
        assert_eq!(report.admitted_rows, total, "every object in one tick, not {single} per tick");
        ingestor.flush_now(CLOCK + 1_000).await.unwrap();
        assert_eq!(ingestor.health().rows_committed_total, total, "every row once");
        assert_eq!(ingestor.health().objects_consumed_total, objects as u64);
        assert!(lab.spool.pending(100).await.unwrap().is_empty(), "every object acknowledged");
    }));
    let bound = 2 * budget as isize;
    eprintln!("NAN-4749: {objects} objects x {rows} rows ({} KiB decoded each, {single} per group): one tick, peak {} MiB (bound {} MiB)",
        decoded >> 10, peak >> 20, bound >> 20);
    assert!(peak < bound, "peak {} MiB over {} MiB", peak >> 20, bound >> 20);
}

/// Small rows hit the row cap before the byte cap. Count the footer rows
/// of all groups in this tick, then leave the rest pending for the next
/// flush; every object must still be committed and acknowledged once.
#[tokio::test]
async fn several_groups_stop_at_the_row_cap_before_decoding() {
    let lab = Lab::new(256 * 1024 * 1024);
    let (objects, rows) = (16, 5_000);
    let mut template = event(0);
    template["raw_data"] = json!("x");
    template["raw_data_size"] = json!(1);
    let mut decoded = 0;
    for object in 0..objects {
        let events = (object * rows..(object + 1) * rows).map(|i| {
            let mut event = template.clone();
            event["message"] = json!(format!("thin-{i:06} {}", "x".repeat(64)));
            event["metadata"]["uid"] = json!(format!("thin-{i:06}"));
            event
        }).collect::<Vec<_>>();
        decoded = lab.land(&format!("thin-{object:02}"), &events, CLOCK - 5_000);
    }
    let (heap, arrow) = decoded_admission_cost(decoded);
    assert!(objects as f64 * arrow < super::super::memory::buffer_cap(lab.config.buffer_budget_bytes) as f64);
    assert!(!super::super::memory::admission_fits(lab.config.buffer_budget_bytes, 0, objects as f64 * heap, objects as f64 * arrow),
        "the fixture needs several groups");
    let mut ingestor = lab.open().await;
    let first = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(first.admitted_rows, (FLUSH_MAX_ROWS / rows * rows) as u64);
    assert!(first.admitted_rows < (objects * rows) as u64);
    ingestor.flush_now(CLOCK + 1_000).await.unwrap();
    assert!(!lab.spool.pending(100).await.unwrap().is_empty());
    ingestor.tick(CLOCK + 2_000).await.unwrap();
    ingestor.flush_now(CLOCK + 3_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, (objects * rows) as u64);
    assert_eq!(ingestor.health().objects_consumed_total, objects as u64);
    assert!(lab.spool.pending(100).await.unwrap().is_empty());
}

/// Rows across several rayon chunks on the production path: every row
/// commits once (stamp strip, event time and uid keys chunked).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_post_decode_work_commits_every_row_once() {
    let lab = Lab::new(2 * 1024 * 1024 * 1024);
    let rows = 3 * super::super::schema::DECODE_CHUNK_ROWS + 17;
    lab.land("wide", &(0..rows).map(event).collect::<Vec<_>>(), CLOCK - 5_000);
    let mut ingestor = lab.open().await;
    let report = ingestor.tick(CLOCK).await.unwrap();
    let health = ingestor.health();
    assert_eq!((report.admitted_rows, health.rows_rejected_total, health.objects_quarantined_total), (rows as u64, 0, 0));
    ingestor.flush_now(CLOCK + 1_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, rows as u64, "every row once");
    assert!(lab.spool.pending(10).await.unwrap().is_empty());
}

/// The chunked per-row work equals the serial one row for row: the risk
/// fields are stripped from every row of every chunk, event times and uid
/// window keys are row-aligned.
#[test]
fn chunked_post_decode_work_matches_the_serial_result() {
    let rows = 3 * super::super::schema::DECODE_CHUNK_ROWS + 17;
    let make = || (0..rows).map(|i| {
        let mut event = event(i);
        event["nano_ioc_ips"] = json!(["10.0.0.1"]);
        event["unmapped"]["nano_compact_finding"] = json!("forged");
        event["unmapped"]["nano_finding_outbox_trusted"] = json!(true);
        if i % 1_000 == 7 {
            event["time"] = json!("not a time");
        }
        crate::iceberg::EventRow { event_uid: format!("nan4749-{i:07}"), event_kind: crate::iceberg::EventKind::Source, ocsf_event: event }
    }).collect::<Vec<_>>();
    let (mut serial, mut chunked) = (make(), make());
    serial.iter_mut().for_each(|row| strip_untrusted_risk_fields(&mut row.ocsf_event));
    for_each_row_chunk(&mut chunked, |chunk| {
        chunk.iter_mut().for_each(|row| strip_untrusted_risk_fields(&mut row.ocsf_event));
        Ok(())
    }).unwrap();
    assert!(serial.iter().zip(&chunked).all(|(a, b)| a.ocsf_event == b.ocsf_event));
    assert!(chunked.iter().all(|row| row.ocsf_event.get("nano_ioc_ips").is_none()
        && row.ocsf_event["unmapped"].get("nano_compact_finding").is_none()
        && row.ocsf_event["unmapped"].get("nano_finding_outbox_trusted").is_none()));
    let times = map_rows(&chunked, |row| event_time_us(&row.ocsf_event).ok());
    let serial_times = serial.iter().map(|row| event_time_us(&row.ocsf_event).ok()).collect::<Vec<_>>();
    assert_eq!(times, serial_times);
    assert_eq!(times.iter().filter(|t| t.is_none()).count(), (0..rows).filter(|i| i % 1_000 == 7).count());
    assert_eq!(super::super::prevalence::stamp_artifacts_of(&chunked).unwrap(),
        super::super::prevalence::stamp_artifacts(serial.iter().map(|row| &row.ocsf_event)).unwrap());
    let window = super::super::dedup::UidWindow::new(TENANT, crate::parts::DedupPolicy::default());
    let uids = chunked.iter().map(|row| row.event_uid.clone()).collect::<Vec<_>>();
    assert_eq!(map_rows(&uids, |uid| window.key(uid)), uids.iter().map(|uid| window.key(uid)).collect::<Vec<_>>());
}

/// Micro-bench (release, ignored): the post-decode per-row work serial vs
/// chunked on the rayon pool, on 64k wide rows (a full flush).
/// cargo test --release -p nanosiem-lake-worker --lib nan4749_post_decode_bench -- --ignored --nocapture
#[test]
#[ignore]
fn nan4749_post_decode_bench() {
    let rows = 65_536;
    let make = || (0..rows).map(|i| {
        let mut event = event(i);
        event["nano_ioc_ips"] = json!(["10.0.0.1"]);
        crate::iceberg::EventRow { event_uid: format!("nan4749-{i:07}"), event_kind: crate::iceberg::EventKind::Source, ocsf_event: event }
    }).collect::<Vec<_>>();
    let window = super::super::dedup::UidWindow::new(TENANT, crate::parts::DedupPolicy::default());
    let run = |rows: &mut Vec<crate::iceberg::EventRow>, chunked: bool| {
        let started = std::time::Instant::now();
        if chunked {
            for_each_row_chunk(rows, |chunk| {
                chunk.iter_mut().for_each(|row| strip_untrusted_risk_fields(&mut row.ocsf_event));
                Ok(())
            }).unwrap();
            let _ = super::super::prevalence::stamp_artifacts_of(rows).unwrap();
            for_each_row_chunk(rows, |chunk| {
                chunk.iter_mut().for_each(|row| super::super::prevalence::strip_stamps(&mut row.ocsf_event));
                Ok(())
            }).unwrap();
            let times = map_rows(rows, |row| event_time_us(&row.ocsf_event).ok());
            let uids = rows.iter().map(|row| row.event_uid.clone()).collect::<Vec<_>>();
            let keys = map_rows(&uids, |uid| window.key(uid));
            assert_eq!((times.len(), keys.len()), (rows.len(), rows.len()));
        } else {
            rows.iter_mut().for_each(|row| strip_untrusted_risk_fields(&mut row.ocsf_event));
            let _ = super::super::prevalence::stamp_artifacts(rows.iter().map(|row| &row.ocsf_event)).unwrap();
            rows.iter_mut().for_each(|row| super::super::prevalence::strip_stamps(&mut row.ocsf_event));
            let times = rows.iter().map(|row| event_time_us(&row.ocsf_event).ok()).collect::<Vec<_>>();
            let keys = rows.iter().map(|row| window.key(&row.event_uid)).collect::<Vec<_>>();
            assert_eq!((times.len(), keys.len()), (rows.len(), rows.len()));
        }
        started.elapsed().as_secs_f64() * 1e3
    };
    for round in 0..3 {
        let (mut serial, mut chunked) = (make(), make());
        let s = run(&mut serial, false);
        let c = run(&mut chunked, true);
        assert!(serial.iter().zip(&chunked).all(|(a, b)| a.ocsf_event == b.ocsf_event), "same rows");
        eprintln!("NAN-4749 round {round}: {rows} rows post-decode serial {s:.0} ms, chunked {c:.0} ms ({:.1}x) on {} rayon threads",
            s / c, rayon::current_num_threads());
    }
}
