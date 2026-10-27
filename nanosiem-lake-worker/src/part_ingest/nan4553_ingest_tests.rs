// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4553 on a real ingestor: one bronze object too large for the
//! ingest working budget is admitted in row slices, so admission stays
//! within the budget however large the object is.
//!
//! the hosted Tenzir canary tenant (~150 eps, placed at 6 eps): its
//! 512 MiB ingest role gets `memory_cap_bytes` 205 MiB (the eps budget's
//! ingest cap) and a 64 MiB working budget. A 10k-row object of the
//! raw-log mix (1.66 MB compressed, ~15 MB decoded) was admitted whole
//! after every restart ("the first object from idle always goes"): one
//! admission peaked at ~1.45x its modelled JSON heap (~330 MiB), and with
//! the process base beside it the cgroup OOM-killed ingest every 2-3 min,
//! after which the crash ledger quarantined the object as "poison".

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;

const TENANT: &str = "45530000-0000-4000-8000-000000000001";
const BASE_HOUR: i64 = 492_096;
const CLOCK: i64 = BASE_HOUR * 3_600_000 + 600_000;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4553", ed25519_dalek::SigningKey::from_bytes(&[53; 32])).unwrap()
}

/// A raw-log-blaster-shaped row: a ~1.5 KB raw event with varying fields.
fn event(i: usize) -> Value {
    event_sized(i, 1)
}

/// `event` with its raw log repeated `fat` times (a wider source).
fn event_sized(i: usize, fat: usize) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + (i as i64 % 3_000), 0).unwrap();
    let uid = format!("nan4553-{i:06}");
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
            .get_or_insert_with(|| parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(),
                Some(parquet::file::properties::WriterProperties::builder().set_compression(parquet::basic::Compression::ZSTD(Default::default())).build())).unwrap())
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

fn notice(key: &str, at: i64) -> SourceNotice {
    SourceNotice { tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: at }
}

/// The FP canary's ingest memory cap: min(512 MiB role, 40% of the 6-eps
/// budget's 512 MiB) rounded up to a MiB (`budget.rs`, `supervisor.rs`).
const FP_CANARY_MEMORY_CAP: u64 = 205 * 1024 * 1024;

struct Lab {
    _root: tempfile::TempDir,
    root: std::path::PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: LocalPartSigner,
    config: IngestConfig,
}

impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
        let mut config = IngestConfig::new(TENANT, root.join("work"));
        // Admitted rows stay buffered (unacknowledged) until a flush.
        config.flush_interval_override_ms = Some(3_600_000);
        config.prevalence_enabled = false;
        size_for_memory_cap(&mut config, FP_CANARY_MEMORY_CAP);
        Self {
            parts: LocalObjectStore::new(root.join("parts")).unwrap(),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), TENANT).unwrap(),
            signer: signer(),
            config,
            _root: dir,
            root,
        }
    }

    fn land(&self, name: &str, events: &[Value], at: i64) -> u64 {
        let key = format!("bronze/{name}.parquet");
        let path = self.root.join("sources").join(&key);
        write_bronze(&path, events);
        self.spool.deliver(&notice(&key, at)).unwrap();
        crate::bronze::bronze_file_decoded_bytes(&path).unwrap()
    }

    async fn open(&self) -> Ingestor<'_> {
        Ingestor::open(self.config.clone(), &self.parts, &self.sources, &self.spool as &dyn NoticeQueue, &self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens")
    }
}

/// Heap high-water mark of `work` above its start, counting this thread,
/// the Tokio blocking pool and the rayon pool admission parses on (a
/// private pool, so parallel tests are never counted).
fn measured<T: Send>(work: impl FnOnce(&tokio::runtime::Runtime) -> T + Send) -> (T, isize) {
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

/// The canary's failure through the production path: an object too large
/// for the working budget is admitted after a crash (alone, from idle),
/// within the budget, sliced, and commits as ONE object with every row.
/// The same bound holds for an object twice as large: admission memory no
/// longer grows with the object.
#[test]
fn an_object_too_large_for_the_budget_is_admitted_in_slices_within_it() {
    let budget = buffer_budget_for(FP_CANARY_MEMORY_CAP);
    assert_eq!(budget, 64 * 1024 * 1024, "the FP canary's working budget");
    // Peak bound: the working budget plus the fixed admission scratch (the
    // Parquet reader of the object, the slice writer, Arrow decode copies).
    let bound = 2 * budget as isize;
    let mut peaks = Vec::new();
    for fat in [1, 2] {
        let lab = Lab::new();
        let rows = 10_000;
        let decoded = lab.land("canary", &(0..rows).map(|i| event_sized(i, fat)).collect::<Vec<_>>(), CLOCK - 5_000);
        let (heap, arrow) = decoded_admission_cost(decoded);
        assert!(!super::super::memory::admission_fits(budget, 0, heap, arrow),
            "fixture must not fit whole: {decoded} decoded bytes model {} MiB", (heap as u64) >> 20);
        // A process admitted it and died before its flush (the ledger it
        // left behind): the restarted process admits the suspect alone,
        // from idle, which before NAN-4553 meant whole.
        std::fs::create_dir_all(lab.root.join("work")).unwrap();
        AdmissionAttempts::open(&lab.root.join("work")).begin([object_id("bronze/canary.parquet", "1").as_str()], true).unwrap();
        let (_, peak) = measured(|runtime| runtime.block_on(async {
            let mut ingestor = lab.open().await;
            let report = ingestor.tick(CLOCK).await.unwrap();
            assert_eq!(report.admitted_rows, rows as u64, "the whole object, in slices");
            assert_eq!(ingestor.health().objects_admitted_in_slices_total, 1);
            ingestor.flush_now(CLOCK + 1_000).await.unwrap();
            assert_eq!(ingestor.health().rows_committed_total, rows as u64);
            assert_eq!(ingestor.health().objects_consumed_total, 1, "one source object, not one per slice");
            assert_eq!(ingestor.health().objects_rejected_total, 0);
            assert!(ingestor.quarantine_entries().unwrap().is_empty(), "nothing quarantined");
            assert!(lab.spool.pending(10).await.unwrap().is_empty(), "acknowledged");
        }));
        let leftovers = std::fs::read_dir(lab.root.join("work/src")).unwrap().count();
        assert_eq!(leftovers, 0, "slice files are removed");
        let unsliced = (heap * super::super::memory::ADMISSION_PEAK_PER_MODELLED_HEAP) as isize;
        eprintln!("NAN-4553: {rows} rows x{fat}, {} MiB decoded: admission peak {} MiB (bound {} MiB; whole-object model {} MiB)",
            decoded >> 20, peak >> 20, bound >> 20, unsliced >> 20);
        assert!(peak < bound, "x{fat}: peak {} MiB over {} MiB", peak >> 20, bound >> 20);
        assert!(peak < unsliced / 2, "x{fat}: slicing must cut the whole-object peak");
        peaks.push(peak);
    }
    // Twice the object, not twice the memory.
    assert!(peaks[1] < peaks[0] * 3 / 2, "peak grew with the object: {peaks:?}");
}

/// Refusals keep their meaning when an object is sliced: refused rows are
/// one `rows` rejection of the object (the kept rows commit), and an object
/// whose every row is refused is refused whole and quarantined, exactly as
/// unsliced.
#[tokio::test(flavor = "current_thread")]
async fn a_sliced_object_refuses_rows_and_whole_objects_like_an_unsliced_one() {
    let lab = Lab::new();
    let rows = 10_000;
    let mut events = (0..rows).map(event).collect::<Vec<_>>();
    for index in [17, 9_001] {
        events[index]["time"] = json!("not a time");
    }
    lab.land("mixed", &events, CLOCK - 5_000);
    let mut ingestor = lab.open().await;
    let report = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(ingestor.health().objects_admitted_in_slices_total, 1);
    assert_eq!(report.admitted_rows, rows as u64 - 2);
    assert_eq!(ingestor.health().rows_rejected_total, 2, "refused rows counted once");
    assert_eq!(ingestor.health().objects_rejected_total, 0, "the object itself is kept");
    ingestor.flush_now(CLOCK + 1_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, rows as u64 - 2);
    assert_eq!(ingestor.health().objects_consumed_total, 1, "one source object, not one per slice");
    assert!(lab.spool.pending(10).await.unwrap().is_empty());
    drop(ingestor);

    // Every row refused (no `time` anywhere): refused whole, quarantined.
    let mut events = (0..rows).map(|i| event(rows + i)).collect::<Vec<_>>();
    for event in &mut events {
        event["metadata"]["uid"] = Value::Null;
    }
    lab.land("refused", &events, CLOCK + 2_000);
    let mut ingestor = lab.open().await;
    let report = ingestor.tick(CLOCK + 3_000).await.unwrap();
    assert_eq!(report.admitted_rows, 0);
    assert_eq!(ingestor.health().objects_admitted_in_slices_total, 1);
    assert_eq!(ingestor.health().objects_rejected_total, 1);
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.len(), 1, "kept for a replay, whole");
    assert_eq!((entries[0].source_key.as_str(), entries[0].rows_rejected), ("bronze/refused.parquet", rows as u64));
    let kept = lab.root.join("work/bronze-quarantine").join(format!("{}.parquet", entries[0].id));
    assert_eq!(crate::parts::sha256_hex(&std::fs::read(&kept).unwrap()), entries[0].id, "the original bytes, not a slice");
    ingestor.flush_now(CLOCK + 4_000).await.unwrap();
    assert!(lab.spool.pending(10).await.unwrap().is_empty());
}

/// An object that fits is never sliced (the common path is unchanged).
#[tokio::test(flavor = "current_thread")]
async fn an_object_that_fits_is_admitted_whole() {
    let lab = Lab::new();
    lab.land("small", &(0..500).map(event).collect::<Vec<_>>(), CLOCK - 5_000);
    let mut ingestor = lab.open().await;
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, 500);
    assert_eq!(ingestor.health().objects_admitted_in_slices_total, 0);
}
