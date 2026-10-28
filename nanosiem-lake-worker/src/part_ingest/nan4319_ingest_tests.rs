// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4319 on a real ingestor: (1) an object ingest[T] dies with (an OOM
//! SIGKILL: no error, no refusal) is refused whole and quarantined after
//! [`MAX_ADMISSION_CRASHES`] crashes with it alone in flight (NAN-4542)
//! instead of wedging the tenant, and the
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
    // NAN-4542: the first crash had both objects in flight and charges
    // neither; each later one has the suspect alone in flight and counts.
    for restart in 0..=MAX_ADMISSION_CRASHES as i64 {
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

/// NAN-4542 (the `kill -9` replay lost 10-30 of 2000 rows): after a crash
/// with several objects in flight, a second crash during recovery charges
/// only an object admitted alone, never the healthy ones around it.
/// NAN-4553: recovery admits groups (half the suspects), not one per flush.
#[tokio::test(flavor = "current_thread")]
async fn a_crash_during_recovery_charges_only_the_one_object_in_flight() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let lab = Lab::new(root);
    let open = || lab.open();
    let names = ["a", "b", "c"];
    for (i, name) in names.iter().enumerate() {
        let base = i * 100;
        lab.object(name, &(base..base + 2 + i).map(event).collect::<Vec<_>>(), CLOCK - 5_000 + i as i64);
    }
    let id = |name: &str| object_id(&format!("bronze/{name}.parquet"), "1");

    // All three in flight, then a crash: three suspects, none charged.
    let mut ingestor = open().await.expect("ingest opens");
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, 2 + 3 + 4);
    drop(ingestor);
    let ledger = AdmissionAttempts::open(&root.join("work"));
    assert_eq!(names.map(|name| ledger.suspect(&id(name))), [Some(0); 3]);
    assert_eq!(ledger.group_limit(), 2, "half the suspects go together");

    // Recovery: `a` and `b` together, flushed on the next tick without
    // waiting the flush age, and nothing beside them.
    let mut ingestor = open().await.expect("ingest opens");
    assert_eq!(ingestor.tick(CLOCK + 1_000).await.unwrap().admitted_rows, 2 + 3, "the oldest half of the suspects");
    let report = ingestor.tick(CLOCK + 1_001).await.unwrap();
    assert_eq!(report.admitted_rows, 0, "nothing joins the suspects' flush");
    assert!(report.flushed_parts > 0, "the suspects' flush is due a tick later");
    assert_eq!(lab.spool.pending(10).await.unwrap().len(), 1, "a and b committed and acknowledged");
    // `c` alone (the only suspect left); then a crash.
    assert_eq!(ingestor.tick(CLOCK + 1_002).await.unwrap().admitted_rows, 4, "the last suspect alone");
    drop(ingestor);

    // The second crash charges `c` (alone in flight), nothing else.
    let ledger = AdmissionAttempts::open(&root.join("work"));
    assert_eq!((ledger.suspect(&id("a")), ledger.suspect(&id("b")), ledger.suspect(&id("c"))), (None, None, Some(1)));
    let mut ingestor = open().await.expect("ingest opens");
    for t in 0..4 {
        ingestor.tick(CLOCK + 2_000 + t).await.unwrap();
    }
    assert!(lab.spool.pending(10).await.unwrap().is_empty(), "c commits");
    assert_eq!(ingestor.health().objects_admission_crashed_total, 0, "nothing refused as poison");
    assert_eq!(ingestor.health().rows_committed_total, 4);
}

/// The production constructor over local stores (the same `Ingestor::open`
/// as `cell.rs`), with admitted rows held until a flush is due.
struct Lab {
    root: std::path::PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: LocalPartSigner,
    config: IngestConfig,
    seed: Schema,
}

impl Lab {
    fn new(root: &std::path::Path) -> Self {
        std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
        let mut config = IngestConfig::new(TENANT, root.join("work"));
        config.flush_interval_override_ms = Some(3_600_000);
        config.prevalence_enabled = false;
        Self {
            root: root.to_path_buf(),
            parts: LocalObjectStore::new(root.join("parts")).unwrap(),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), TENANT).unwrap(),
            signer: signer(),
            config,
            seed: seed_schema(),
        }
    }

    async fn open(&self) -> Result<Ingestor<'_>> {
        Ingestor::open(self.config.clone(), &self.parts, &self.sources, &self.spool as &dyn NoticeQueue, &self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &self.seed, CLOCK).await
    }

    fn object(&self, name: &str, events: &[Value], at: i64) {
        write_bronze(&self.root.join(format!("sources/bronze/{name}.parquet")), events);
        self.spool.deliver(&notice(&format!("bronze/{name}.parquet"), at)).unwrap();
    }
}

/// NAN-4553 (review P2): recovery bisects. 16 objects in flight, one of
/// them kills ingest whenever it is admitted. Recovery used to flush every
/// suspect alone (15 healthy flushes; up to ~512 on a full buffer); now
/// groups halve around the culprit: log2(16) - 1 more crashes to corner it,
/// [`MAX_ADMISSION_CRASHES`] alone to refuse it, and a handful of flushes.
#[tokio::test(flavor = "current_thread")]
async fn recovery_bisects_suspects_instead_of_flushing_each_alone() {
    const POISON_ROWS: u64 = 50;
    let root = tempfile::tempdir().unwrap();
    let lab = Lab::new(root.path());
    for i in 0..16_usize {
        let rows = if i == 9 { POISON_ROWS as usize } else { 2 };
        lab.object(&format!("o{i:02}"), &(i * 100..i * 100 + rows).map(event).collect::<Vec<_>>(), CLOCK - 20_000 + i as i64);
    }
    let (mut crashes, mut flushes, mut now) = (0_u32, 0_u32, CLOCK);
    // Health is per process: commits before a crash stay committed.
    let mut committed = 0;
    let mut done = false;
    'process: for _ in 0..32 {
        let mut ingestor = lab.open().await.expect("ingest opens");
        for _ in 0..64 {
            now += 1;
            let report = ingestor.tick(now).await.unwrap();
            if report.flushed_parts > 0 {
                flushes += 1;
            }
            if report.admitted_rows >= POISON_ROWS {
                // The poison object is in flight: ingest dies (SIGKILL).
                crashes += 1;
                committed += ingestor.health().rows_committed_total;
                continue 'process;
            }
            if lab.spool.pending(32).await.unwrap().is_empty() {
                assert_eq!(ingestor.health().objects_admission_crashed_total, 1, "the poison object, nothing else");
                assert_eq!(committed + ingestor.health().rows_committed_total, 15 * 2, "every healthy row committed");
                // The next tick drops acknowledged objects from the ledger.
                ingestor.tick(now + 1).await.unwrap();
                done = true;
                break 'process;
            }
        }
        panic!("recovery stalled: {:?}", ingestor.health());
    }
    assert!(done);
    // 1 (all 16 in flight) + 3 (groups of 8, 4, 2) + MAX alone.
    assert_eq!(crashes, 1 + 3 + MAX_ADMISSION_CRASHES, "crashes to name the culprit");
    eprintln!("NAN-4553 bisection: 16 suspects, {crashes} crashes, {flushes} flushes");
    assert!(flushes <= 6, "{flushes} flushes (each suspect alone took 15)");
    let ledger = AdmissionAttempts::open(&lab.root.join("work"));
    assert!(ledger.is_empty(), "recovery over");
    let ingestor = lab.open().await.unwrap();
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.iter().map(|entry| (entry.source_key.as_str(), entry.rows_rejected)).collect::<Vec<_>>(),
        [("bronze/o09.parquet", POISON_ROWS)], "only the culprit is quarantined");
}

/// NAN-4553 (review P2): an object is recorded before its source fetch,
/// digest and footer read, so a death there is charged. Here the fetch
/// fails (the process ends in it) and the next process finds it charged.
#[tokio::test(flavor = "current_thread")]
async fn an_object_is_recorded_before_its_fetch() {
    let root = tempfile::tempdir().unwrap();
    let lab = Lab::new(root.path());
    // A directory where the object should be: the fetch errors.
    std::fs::create_dir_all(lab.root.join("sources/bronze/stuck.parquet")).unwrap();
    lab.spool.deliver(&notice("bronze/stuck.parquet", CLOCK - 1_000)).unwrap();
    let mut ingestor = lab.open().await.unwrap();
    assert!(ingestor.tick(CLOCK).await.is_err(), "the fetch fails");
    // An in-process retry is the same process: charged once.
    assert!(ingestor.tick(CLOCK + 1).await.is_err());
    drop(ingestor);
    let id = object_id("bronze/stuck.parquet", "1");
    assert_eq!(AdmissionAttempts::open(&lab.root.join("work")).suspect(&id), Some(1),
        "the process ended inside the fetch with the object offered alone: charged");

    // The object is readable again: admitted alone, committed, forgotten.
    std::fs::remove_dir(lab.root.join("sources/bronze/stuck.parquet")).unwrap();
    write_bronze(&lab.root.join("sources/bronze/stuck.parquet"), &(0..3).map(event).collect::<Vec<_>>());
    let mut ingestor = lab.open().await.unwrap();
    assert_eq!(ingestor.tick(CLOCK + 1_000).await.unwrap().admitted_rows, 3);
    ingestor.tick(CLOCK + 1_001).await.unwrap();
    assert!(lab.spool.pending(10).await.unwrap().is_empty());
    ingestor.tick(CLOCK + 1_002).await.unwrap();
    assert!(AdmissionAttempts::open(&lab.root.join("work")).is_empty());
}

/// NAN-4553: an object whose refusal itself died (the refusal reads the
/// footer for the row count) is refused without reading it again.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_that_died_skips_the_footer() {
    let root = tempfile::tempdir().unwrap();
    let lab = Lab::new(root.path());
    std::fs::write(lab.root.join("sources/bronze/bad-footer.parquet"), b"PAR1 not a parquet footer").unwrap();
    lab.spool.deliver(&notice("bronze/bad-footer.parquet", CLOCK - 1_000)).unwrap();
    let id = object_id("bronze/bad-footer.parquet", "1");
    std::fs::create_dir_all(lab.root.join("work")).unwrap();
    for _ in 0..=MAX_ADMISSION_CRASHES {
        AdmissionAttempts::open(&lab.root.join("work")).begin([id.as_str()], true).unwrap();
    }
    let mut ingestor = lab.open().await.unwrap();
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, 0);
    assert_eq!(ingestor.health().objects_admission_crashed_total, 1);
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!((entries.len(), entries[0].rows_rejected), (1, 0), "kept for replay; rows unknown");
    ingestor.flush_now(CLOCK + 1).await.unwrap();
    assert!(lab.spool.pending(10).await.unwrap().is_empty(), "acknowledged: later data flows");
}

/// NAN-4553 (review P1): a coded exit (a handled fatal error) undoes this
/// process's charge; a crash keeps it.
#[tokio::test(flavor = "current_thread")]
async fn a_coded_exit_is_not_charged_as_a_crash() {
    let root = tempfile::tempdir().unwrap();
    let lab = Lab::new(root.path());
    lab.object("a", &(0..3).map(event).collect::<Vec<_>>(), CLOCK - 1_000);
    let id = object_id("bronze/a.parquet", "1");
    let mut ingestor = lab.open().await.unwrap();
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, 3, "admitted alone from idle: charged");
    ingestor.note_orderly_exit("ingest writer epoch changed; restart required");
    drop(ingestor);
    assert_eq!(AdmissionAttempts::open(&lab.root.join("work")).suspect(&id), Some(0), "a suspect, not charged");

    let mut ingestor = lab.open().await.unwrap();
    assert_eq!(ingestor.tick(CLOCK + 1_000).await.unwrap().admitted_rows, 3);
    drop(ingestor); // SIGKILL
    assert_eq!(AdmissionAttempts::open(&lab.root.join("work")).suspect(&id), Some(1), "a crash is charged");
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
    // Each object's decoded cost fills an admission group on its own, so
    // they decode one after another (NAN-4749: in the same tick, the first
    // group's JSON values freed before the second decodes).
    let (one_heap, one_arrow) = decoded_admission_cost(crate::bronze::bronze_file_decoded_bytes(
        &root.join("sources").join("bronze/landing-0.parquet")).unwrap());
    assert!(!super::super::memory::admission_fits(config.buffer_budget_bytes, 0, 2.0 * one_heap, 2.0 * one_arrow),
        "one landing object per admission group on a 1.2 GB role");
    assert_eq!(report.admitted_rows, 20_000);
    let mut now = CLOCK;
    while ingestor.health().rows_committed_total < 20_000 {
        now += 1_000;
        ingestor.tick(now).await.unwrap();
        ingestor.flush_now(now).await.unwrap();
        assert!(now < CLOCK + 20_000, "stalled: {:?}", ingestor.health());
    }
    assert!(spool.pending(10).await.unwrap().is_empty());
}

/// NAN-4553 (review P1): each coded exit class keeps or undoes the charges.
#[test]
fn coded_exits_are_classified_by_whether_the_object_can_cause_them() {
    use crate::part_ingest::r2_put::TerminalPutError;
    let put = |status| anyhow::Error::new(TerminalPutError { key: "lake/parts/v1/x".into(), status, code: "c".into() });
    // Kept: the object in flight may be the cause.
    assert!(exit_keeps_charges(Some(&anyhow::anyhow!("decode failed").context(RetryWindowExhausted(1_800)))), "retry window");
    assert!(exit_keeps_charges(Some(&put(400).context("flush"))), "400 BadDigest on its part");
    assert!(exit_keeps_charges(Some(&put(422))), "another 4xx on its part");
    // Undone: never the object's.
    assert!(!exit_keeps_charges(None), "a clean end");
    assert!(!exit_keeps_charges(Some(&put(403))), "403: credentials");
    assert!(!exit_keeps_charges(Some(&put(401))), "401: credentials");
    assert!(!exit_keeps_charges(Some(&anyhow::Error::new(crate::parts::part_log::Fenced { seq: 7 }))), "fencing");
    assert!(!exit_keeps_charges(Some(&anyhow::Error::new(crate::parts::part_log::DoubleConsume { key: "k".into() }))), "double consume");
    assert!(!exit_keeps_charges(Some(&anyhow::Error::new(crate::edge_log::EdgeLogFenced))), "edge log fenced");
    assert!(!exit_keeps_charges(Some(&anyhow::Error::new(super::super::writer_lease::LeaseLost { epoch: 3, reason: "r".into() }))), "lease lost");
    assert!(!exit_keeps_charges(Some(&anyhow::anyhow!("ingest writer epoch changed; restart required"))), "epoch change");
    assert!(!exit_keeps_charges(Some(&anyhow::anyhow!("credentials expired and refresh gave up"))), "credentials");
    assert!(!exit_keeps_charges(Some(&anyhow::anyhow!("enrichment refresh: owner 503"))), "enrichment");
}

/// NAN-4553 (review P1): an object that fails every tick WITHOUT crashing
/// (here: its fetch always errors) and so exits through the retry window
/// keeps its charge each cycle and is refused and quarantined after
/// MAX_ADMISSION_CRASHES exits; it no longer loops forever at charge 0
/// (with #7843 alone it was never charged past 1 and stalled the tenant).
/// The same object exiting through a never-the-object's path is not charged.
#[tokio::test(flavor = "current_thread")]
async fn an_object_failing_every_tick_is_refused_after_bounded_window_exits() {
    let root = tempfile::tempdir().unwrap();
    let lab = Lab::new(root.path());
    std::fs::create_dir_all(lab.root.join("sources/bronze/stuck.parquet")).unwrap();
    lab.spool.deliver(&notice("bronze/stuck.parquet", CLOCK - 1_000)).unwrap();
    let id = object_id("bronze/stuck.parquet", "1");
    let work = lab.root.join("work");

    // An exit that is never the object's undoes the charge.
    let mut ingestor = lab.open().await.unwrap();
    let error = ingestor.tick(CLOCK).await.unwrap_err();
    ingestor.note_coded_exit(Some(&error.context("ingest writer epoch changed; restart required")), "epoch");
    drop(ingestor);
    assert_eq!(AdmissionAttempts::open(&work).suspect(&id), Some(0), "not the object's: uncharged");

    let mut now = CLOCK + 1_000;
    for cycle in 1..=MAX_ADMISSION_CRASHES {
        let mut ingestor = lab.open().await.unwrap();
        let error = ingestor.tick(now).await.unwrap_err();
        // The run loop's window exit (MAX_RETRY_WINDOW of failing ticks).
        let exit = error.context(RetryWindowExhausted(1_800));
        ingestor.note_coded_exit(Some(&exit), &format!("{exit:#}"));
        drop(ingestor);
        assert_eq!(AdmissionAttempts::open(&work).suspect(&id), Some(cycle), "window exit {cycle} keeps the charge");
        now += 1_000;
    }
    // Its bytes read again (the refusal keeps them for an operator replay;
    // a refusal whose own fetch fails retries, so nothing is ever dropped
    // unkept): refused, not admitted a fourth time.
    std::fs::remove_dir(lab.root.join("sources/bronze/stuck.parquet")).unwrap();
    write_bronze(&lab.root.join("sources/bronze/stuck.parquet"), &(0..3).map(event).collect::<Vec<_>>());
    let mut ingestor = lab.open().await.unwrap();
    assert_eq!(ingestor.tick(now).await.unwrap().admitted_rows, 0, "refused after the bounded window exits, not admitted");
    assert_eq!(ingestor.health().objects_admission_crashed_total, 1);
    assert_eq!(ingestor.quarantine_entries().unwrap().len(), 1, "kept for an operator replay");
    ingestor.flush_now(now + 1).await.unwrap();
    assert!(lab.spool.pending(10).await.unwrap().is_empty(), "acknowledged as rejected: the tenant's later data flows");
}
