// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4336 on a real ingestor. Future-dated rows used to wedge a tenant's
//! ingest: control's reserve guard refuses a part whose `max_event_time` is
//! more than 5 min past its clock (HTTP 400), the owner reported that as a
//! 503, and ingest[T] retried the same flush until wall-clock time caught up
//! (hours), head-of-line blocking every later object.
//!
//! The part store here enforces that same guard on every part write
//! ([`ReserveGuard`], the owner's answer: 422 `writer_reservation_refused`),
//! so these tests go through the production admission, flush and part
//! publication path:
//! 1. a landed file 14 h in the future lands at once, searchable at its
//!    ingest time, with `metadata.original_time` kept;
//! 2. a bronze object straight off the edge log (Vector/HEC) is clamped by
//!    ingest[T] itself, against the time its object reached the edge;
//! 3. a permanent reservation refusal quarantines the object (after the
//!    isolating restart) and the next object flows.

use super::*;
use crate::bronze::{MAX_FUTURE_EVENT_SKEW_MS, TIME_CLAMPED_LABEL};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::native_writer::{OwnerRefused, OWNER_RESERVATION_REFUSED_STATUS};
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

const TENANT: &str = "43360000-0000-4000-8000-000000000001";
/// 2026-10-21T17:00Z, hours since epoch.
const BASE_HOUR: i64 = 497_945;
/// 17:07:44Z, the D re-upload.
const CLOCK: i64 = BASE_HOUR * 3_600_000 + 464_000;
const FOURTEEN_HOURS_MS: i64 = 14 * 3_600_000;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4336", ed25519_dalek::SigningKey::from_bytes(&[36; 32])).unwrap()
}

/// The part store with the control writer authority's reserve guard in
/// front: a lake part whose `max_event_time` is more than 5 min past the
/// control clock (or whose event hour is `refuse_hour`) is refused exactly
/// as the owner now refuses it (422 `writer_reservation_refused`).
struct ReserveGuard {
    inner: LocalObjectStore,
    control_now_ms: AtomicI64,
    refuse_hour: std::sync::Mutex<Option<i32>>,
    refused: AtomicUsize,
}

impl ReserveGuard {
    fn new(root: &std::path::Path) -> Self {
        Self { inner: LocalObjectStore::new(root).unwrap(), control_now_ms: AtomicI64::new(CLOCK),
            refuse_hour: std::sync::Mutex::new(None), refused: AtomicUsize::new(0) }
    }

    fn reserve(&self, hints: &WriteHints) -> Result<()> {
        if hints.class == WriterClass::LakePart
            && (hints.max_time_ms > self.control_now_ms.load(Ordering::SeqCst) + MAX_FUTURE_EVENT_SKEW_MS
                || *self.refuse_hour.lock().unwrap() == Some(hints.event_hour))
        {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(OwnerRefused { status: OWNER_RESERVATION_REFUSED_STATUS }.into());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ObjectStore for ReserveGuard {
    async fn object_size(&self, key: &str) -> Result<Option<u64>> { self.inner.object_size(key).await }
    async fn modified_ms(&self, key: &str) -> Result<Option<i64>> { self.inner.modified_ms(key).await }
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        self.inner.get_range(key, range).await
    }
    async fn get_to_file(&self, key: &str, path: &std::path::Path) -> Result<bool> { self.inner.get_to_file(key, path).await }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.inner.put_if_absent(key, bytes).await }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> Result<bool> {
        self.reserve(hints)?;
        self.inner.put_if_absent_with(key, bytes, hints).await
    }
    async fn put_file_if_absent_with(&self, key: &str, path: &std::path::Path, sha256_hex: &str, bytes: u64, hints: &WriteHints)
        -> Result<bool> {
        self.reserve(hints)?;
        self.inner.put_file_if_absent_with(key, path, sha256_hex, bytes, hints).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
}

fn event(i: usize, time_ms: i64) -> Value {
    // The `nan2868_part_ingest` fixture shape (it passes bronze admission).
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(time_ms).unwrap();
    let uid = format!("nan4336-{i:05}");
    let raw = format!("raw {uid} token{i}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("token logon {i}"), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "hec_skewed",
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

/// Every committed row, read back from the parts' data files as JSON.
async fn committed_rows(parts: &ReserveGuard, ingestor: &Ingestor<'_>) -> Vec<Value> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let live = ingestor.live_parts().into_iter().map(|part| part.part_id.to_string()).collect::<BTreeSet<_>>();
    let mut rows = Vec::new();
    for key in parts.list("").await.unwrap() {
        if !key.ends_with(".parquet") || !key.contains("/data-") || !live.iter().any(|id| key.contains(id.as_str())) {
            continue;
        }
        let bytes = bytes::Bytes::from(parts.get(&key).await.unwrap().unwrap());
        for batch in ParquetRecordBatchReaderBuilder::try_new(bytes).unwrap().build().unwrap() {
            let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
            writer.write(&batch.unwrap()).unwrap();
            writer.finish().unwrap();
            for line in writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                rows.push(serde_json::from_slice::<Value>(line).unwrap());
            }
        }
    }
    rows
}

fn time_ms(row: &Value) -> i64 {
    crate::iceberg::ocsf_time_millis(row.get("time")).unwrap()
}

/// Acceptance 1: the D fixture shape (Tenzir 3002 rows, 1 s apart), here
/// starting 14 h in the future, through landing conversion and ingest[T].
#[tokio::test(flavor = "current_thread")]
async fn a_landed_file_14h_in_the_future_lands_at_once_searchable_at_ingest_time() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = ReserveGuard::new(&root.join("parts"));
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(0);
    config.prevalence_enabled = false;

    let rows = 3_000_usize;
    let first_ms = CLOCK + FOURTEEN_HOURS_MS;
    let file = crate::landing_fixture::tenzir_auth_parquet("future", rows, first_ms);
    let source = crate::landing::LandingSource {
        source_id: uuid::Uuid::nil(), route_key: "tenzir_auth".into(), credential_id: uuid::Uuid::nil(), active: true,
    };
    let stage = nanosiem_core::parsers::landing_ocsf::LandingOcsfStage::new(1).unwrap();
    let converted = crate::landing::convert_file(&file, crate::landing::FileFormat::Parquet, &stage, TENANT, &source,
        chrono::DateTime::from_timestamp_millis(CLOCK).unwrap()).unwrap();
    assert_eq!((converted.rows_accepted, converted.rows_refused, converted.rows_time_clamped), (rows as u64, 0, rows as u64));
    for (index, (_, body, _)) in converted.objects.iter().enumerate() {
        let key = format!("bronze/landing-{index}.parquet");
        std::fs::write(root.join("sources").join(&key), body).unwrap();
        spool.deliver(&SourceNotice { bytes: body.len() as u64, ..notice(&key, CLOCK + 2_000 + index as i64) }).unwrap();
    }

    let mut ingestor = Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");
    // Seconds after the upload, not 14 h: one tick admits and flushes.
    let now = CLOCK + 5_000;
    parts.control_now_ms.store(now, Ordering::SeqCst);
    ingestor.tick(now).await.expect("no reserve refusal, no retry");
    ingestor.flush_now(now).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, rows as u64, "{:?}", ingestor.health());
    assert!(spool.pending(10).await.unwrap().is_empty(), "the edge log moves on");
    assert_eq!(parts.refused.load(Ordering::SeqCst), 0, "the reserve guard never fires");

    // Searchable at ingest time: every part is in the ingest hour, bounded
    // by the conversion time; each row keeps what the source sent.
    let live = ingestor.live_parts();
    assert!(!live.is_empty());
    for part in &live {
        assert_eq!(i64::from(part.event_hour), BASE_HOUR, "{part:?}");
        assert!(part.max_time_us <= CLOCK * 1_000, "{part:?}");
    }
    let committed = committed_rows(&parts, &ingestor).await;
    assert_eq!(committed.len(), rows);
    let originals = committed.iter().map(|row| {
        assert_eq!(time_ms(row), CLOCK, "time = ingest (conversion) time");
        assert!(row["metadata"]["labels"].as_array().unwrap().iter().any(|label| label == TIME_CLAMPED_LABEL), "{row}");
        let original = row["metadata"]["original_time"].as_str().expect("original_time kept");
        chrono::DateTime::parse_from_rfc3339(original).unwrap().timestamp_millis()
    }).collect::<BTreeSet<_>>();
    let expected = (0..rows as i64).map(|i| first_ms + i * 1_000).collect::<BTreeSet<_>>();
    assert_eq!(originals, expected, "every row's original time, to the millisecond");
}

/// Acceptance 1b: a bronze object straight off the edge log (Vector / HEC
/// path, no landing step): ingest[T] clamps against the time the object
/// reached the edge, counts the rows per source, and a crash replay of the
/// same object clamps identically (deterministic, so dedup still holds).
#[tokio::test(flavor = "current_thread")]
async fn ingest_clamps_edge_objects_per_source_and_the_next_object_is_not_held() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = ReserveGuard::new(&root.join("parts"));
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(0);
    config.prevalence_enabled = false;
    let received = CLOCK - 1_000;

    // 4 rows 14 h ahead, 2 within the skew (kept), 2 in the past (kept).
    let mut skewed = (0..4).map(|i| event(i, CLOCK + FOURTEEN_HOURS_MS + i as i64)).collect::<Vec<_>>();
    skewed.push(event(10, received + MAX_FUTURE_EVENT_SKEW_MS - 1_000));
    skewed.push(event(11, received + 60_000));
    skewed.push(event(12, CLOCK - 3_600_000));
    skewed.push(event(13, CLOCK - 7_200_000));
    write_bronze(&root.join("sources/bronze/skewed.parquet"), &skewed);
    write_bronze(&root.join("sources/bronze/after.parquet"), &(100..103).map(|i| event(i, CLOCK - 60_000)).collect::<Vec<_>>());
    spool.deliver(&notice("bronze/skewed.parquet", received)).unwrap();
    spool.deliver(&notice("bronze/after.parquet", received + 1)).unwrap();

    let mut ingestor = Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");
    ingestor.tick(CLOCK).await.expect("no reserve refusal");
    ingestor.flush_now(CLOCK).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 11);
    assert_eq!(ingestor.health().rows_time_clamped_total, 4);
    assert_eq!(ingestor.health().rows_time_clamped_by_source, BTreeMap::from([("hec_skewed".to_string(), 4)]));
    assert!(spool.pending(10).await.unwrap().is_empty());
    assert_eq!(parts.refused.load(Ordering::SeqCst), 0);

    let committed = committed_rows(&parts, &ingestor).await;
    let by_uid = committed.iter().map(|row| (row["metadata"]["uid"].as_str().unwrap().to_string(), row)).collect::<BTreeMap<_, _>>();
    for i in 0..4 {
        let row = by_uid[&format!("nan4336-{i:05}")];
        assert_eq!(time_ms(row), received, "clamped to when the object reached the edge");
        let original = chrono::DateTime::parse_from_rfc3339(row["metadata"]["original_time"].as_str().unwrap()).unwrap();
        assert_eq!(original.timestamp_millis(), CLOCK + FOURTEEN_HOURS_MS + i as i64);
    }
    for (i, expected) in [(10, received + MAX_FUTURE_EVENT_SKEW_MS - 1_000), (11, received + 60_000), (12, CLOCK - 3_600_000)] {
        let row = by_uid[&format!("nan4336-{i:05}")];
        assert_eq!(time_ms(row), expected, "within the skew: untouched");
        assert!(row["metadata"].get("original_time").is_none_or(Value::is_null));
        assert!(row["metadata"].get("labels").is_none_or(|labels| !labels.to_string().contains(TIME_CLAMPED_LABEL)));
    }

    // The clamp is deterministic for an object: admitting it again yields
    // the same rows, so the uid window drops every one as a duplicate.
    let again = crate::bronze::admit_bronze_files_received(
        &[root.join("sources/bronze/skewed.parquet")], TENANT, &BronzeIngestEnricher::disabled(),
        &crate::bronze::IngestTimes {
            received_ms: BTreeMap::from([(root.join("sources/bronze/skewed.parquet"), received)]),
            now_ms: CLOCK + 3_600_000,
        }).unwrap().0;
    let replayed = again.batch.rows().iter().map(|row| (row.event_uid.clone(), time_ms(&row.ocsf_event))).collect::<BTreeMap<_, _>>();
    for i in 0..4 {
        assert_eq!(replayed[&format!("nan4336-{i:05}")], received, "a later replay clamps to the same time");
    }
}

/// Acceptance 2: the owner refuses a flush's part reservation permanently
/// (422). Ingest exits (fatal, never an endless in-process retry), the
/// restarted ingest admits each object of that flush alone, the culprit's
/// own flush is refused and marked, and the next process refuses it whole,
/// quarantines it and acknowledges it, so the object behind it flows.
#[tokio::test(flavor = "current_thread")]
async fn a_permanent_reserve_refusal_quarantines_the_object_and_the_next_seq_flows() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = ReserveGuard::new(&root.join("parts"));
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(0);
    config.prevalence_enabled = false;
    let seed = seed_schema();
    let open = || Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed, CLOCK);

    // seq22 (poison: control refuses its hour) and seq23 behind it.
    let poison_hour = (BASE_HOUR - 2) as i32;
    *parts.refuse_hour.lock().unwrap() = Some(poison_hour);
    write_bronze(&root.join("sources/bronze/seq22.parquet"),
        &(0..5).map(|i| event(i, i64::from(poison_hour) * 3_600_000 + 60_000 + i as i64)).collect::<Vec<_>>());
    write_bronze(&root.join("sources/bronze/seq23.parquet"), &(100..103).map(|i| event(i, CLOCK - 60_000)).collect::<Vec<_>>());
    spool.deliver(&notice("bronze/seq22.parquet", CLOCK - 5_000)).unwrap();
    spool.deliver(&notice("bronze/seq23.parquet", CLOCK - 4_000)).unwrap();

    // Run 1: both in one flush; the owner refuses it. The error is fatal
    // (the cell exits instead of retrying it for hours).
    let mut ingestor = open().await.expect("ingest opens");
    let error = ingestor.tick(CLOCK).await.expect_err("the owner refused the flush");
    assert!(fatal_ingest_error(&error), "{error:#}");
    assert!(crate::part_ingest::native_writer::reservation_refused(&error));
    drop(ingestor);
    assert_eq!(spool.pending(10).await.unwrap().len(), 2, "nothing acknowledged");

    // Run 2: the poison object is admitted and flushed alone; refused again,
    // now it names exactly one object.
    let mut ingestor = open().await.expect("ingest opens");
    let error = ingestor.tick(CLOCK + 1_000).await.expect_err("the culprit's own flush is refused");
    assert!(fatal_ingest_error(&error), "{error:#}");
    drop(ingestor);
    assert!(AdmissionAttempts::open(&root.join("work")).reserve_refused(&object_id("bronze/seq22.parquet", "1")));

    // Run 3: refused whole and quarantined; its rows count as rejected,
    // never as committed.
    let mut ingestor = open().await.expect("ingest opens");
    let report = ingestor.tick(CLOCK + 2_000).await.unwrap();
    assert_eq!(report.admitted_rows, 0);
    assert_eq!(ingestor.health().objects_reserve_refused_total, 1);
    assert_eq!(ingestor.health().objects_admission_crashed_total, 0, "a distinct reason and counter");
    assert_eq!(ingestor.health().objects_rejected_total, 1);
    assert_eq!(ingestor.health().rows_rejected_total, 5);
    assert_eq!(ingestor.health().rows_committed_total, 0);
    let pending = spool.pending(10).await.unwrap();
    assert_eq!(pending.iter().map(|(_, n)| n.key.as_str()).collect::<Vec<_>>(), vec!["bronze/seq23.parquet"],
        "the poison object is acknowledged");
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.len(), 1, "kept for an operator replay");
    assert_eq!((entries[0].source_key.as_str(), entries[0].reason.as_str(), entries[0].rows_rejected),
        ("bronze/seq22.parquet", "admission_invalid", 5));
    assert!(entries[0].detail.starts_with(RESERVE_REFUSED), "{}", entries[0].detail);

    // The next seq flows.
    ingestor.tick(CLOCK + 3_000).await.unwrap();
    ingestor.flush_now(CLOCK + 3_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 3);
    assert!(spool.pending(10).await.unwrap().is_empty());
    ingestor.tick(CLOCK + 4_000).await.unwrap();
    assert!(AdmissionAttempts::open(&root.join("work")).is_empty(), "acknowledged objects leave the ledger");
}

/// Review follow-up: a future-dated row with no `metadata` never holds its
/// object. Its time is clamped like any other (the unit test
/// `a_future_time_is_never_left_in_place_whatever_metadata_looks_like`);
/// OCSF then refuses that one row on its own (`metadata.product` is
/// required), so no future time reaches the reserve guard, the rest of the
/// object lands and the refused row is counted, never quarantining the object.
#[tokio::test(flavor = "current_thread")]
async fn a_future_row_without_metadata_is_clamped_and_its_object_lands() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = ReserveGuard::new(&root.join("parts"));
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(0);
    config.prevalence_enabled = false;

    // A landed NDJSON file: one 14 h-ahead row without `metadata`, one with.
    let future = CLOCK + FOURTEEN_HOURS_MS;
    let mut bare = event(0, future);
    bare.as_object_mut().unwrap().remove("metadata");
    let mut lines = Vec::new();
    for row in [bare, event(1, future)] {
        serde_json::to_writer(&mut lines, &row).unwrap();
        lines.push(b'\n');
    }
    let source = crate::landing::LandingSource {
        source_id: uuid::Uuid::nil(), route_key: "tenzir_auth".into(), credential_id: uuid::Uuid::nil(), active: true,
    };
    let stage = nanosiem_core::parsers::landing_ocsf::LandingOcsfStage::new(1).unwrap();
    let converted = crate::landing::convert_file(&lines, crate::landing::FileFormat::Ndjson { gzip: false }, &stage, TENANT, &source,
        chrono::DateTime::from_timestamp_millis(CLOCK).unwrap()).unwrap();
    assert_eq!((converted.rows_accepted, converted.rows_refused, converted.rows_time_clamped), (1, 1, 1));
    assert_eq!(converted.first_refusal.map(|refusal| refusal.reason), Some("ocsf_attribute_required_missing"));
    for (index, (_, body, _)) in converted.objects.iter().enumerate() {
        let key = format!("bronze/bare-{index}.parquet");
        std::fs::write(root.join("sources").join(&key), body).unwrap();
        spool.deliver(&SourceNotice { bytes: body.len() as u64, ..notice(&key, CLOCK + 1_000) }).unwrap();
    }

    let mut ingestor = Ingestor::open(config.clone(), &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");
    let now = CLOCK + 5_000;
    parts.control_now_ms.store(now, Ordering::SeqCst);
    ingestor.tick(now).await.expect("no reserve refusal");
    ingestor.flush_now(now).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 1, "{:?}", ingestor.health());
    assert_eq!(ingestor.health().objects_reserve_refused_total, 0);
    assert!(spool.pending(10).await.unwrap().is_empty(), "the object lands");
    assert_eq!(parts.refused.load(Ordering::SeqCst), 0, "the reserve guard never fires");
    for row in committed_rows(&parts, &ingestor).await {
        assert_eq!(time_ms(&row), CLOCK, "{row}");
        let original = chrono::DateTime::parse_from_rfc3339(row["metadata"]["original_time"].as_str().unwrap()).unwrap();
        assert_eq!(original.timestamp_millis(), future);
        assert!(row["metadata"]["labels"].as_array().unwrap().iter().any(|label| label == TIME_CLAMPED_LABEL), "{row}");
    }
}
