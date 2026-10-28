// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4674: a backfill whose source objects each span ~166 event hours
//! (Dan's bakeoff 2026-10-27: 21,929 parts for 1.1M rows, ~50 rows a part,
//! admission at 1/7 of the firehose) must coalesce into a few large L0
//! parts per hour, without touching the live lane or custody.
//!
//! Everything runs through the production `Ingestor::open` constructor and
//! its `tick` scheduler, the cell's pipelined flush (background store and
//! signer), real bronze admission, real Parquet/token/partial part builds,
//! real signatures and the real part log. Only the object stores (local
//! directories), the notice queue (the spool, wrapped to check that every
//! ack follows its `add`) and the clock are stand-ins.

use anyhow::Result;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::dedup::read_time_uids;
use nanosiem_lake_worker::part_ingest::discovery::{AckCounts, NoticeHandle};
use nanosiem_lake_worker::part_ingest::ingest::{
    compact_tiny_batches, flush_event_hour_cap, seed_schema, MAX_FLUSH_EVENT_HOURS, TINY_BATCH_ROWS, TINY_BATCH_RUN,
};
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::format::{LogKeys, PartKeys};
use nanosiem_lake_worker::parts::levels::{Level, MergePolicy, FRAGMENTED_HOUR_PARTS};
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, LogEntry, LogOp, ObjectStore, SourceRef};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use nanosiem_lake_worker::parts::sha256_hex;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d4674";
/// 2026-09-25T00:00:00Z: the backfill's first event hour.
const DAY0_S: i64 = 1_790_294_400;
/// Event hours every backfill object spans (the bakeoff's ~166).
const SPAN_HOURS: i64 = 166;
/// Ingest "now": a day after the backfilled week ends.
const NOW_MS: i64 = (DAY0_S + (SPAN_HOURS + 24) * 3_600) * 1_000;

fn event(uid: &str, time_s: i64, i: usize) -> Value {
    let time = chrono::DateTime::from_timestamp(time_s, 0).unwrap();
    let raw = format!("raw {uid} host-{} logon token{}", i % 7, i % 13);
    json!({
        "activity_id": 1,
        "activity_name": "Logon",
        "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management",
        "category_uid": 3,
        "class_name": "Authentication",
        "class_uid": 3002,
        "message": format!("Failed logon for user{} from 10.0.{}.{}", i % 5, i % 3, i % 250),
        "raw_data": raw,
        "raw_data_size": raw.len(),
        "metadata": {
            "log_name": "security",
            "log_source": if i % 3 == 0 { "WINDOWS_EVENT" } else { "CLOUDTRAIL" },
            "product": {"name": "fixture", "vendor_name": "nano"},
            "tenant_uid": TENANT,
            "uid": uid,
            "version": "1.9.0"
        },
        "severity": "Informational",
        "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 3, i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "user": {"name": format!("user{}", i % 5), "uid": format!("S-1-5-21-{}", i % 5)},
        "status": "Failure",
        "status_id": 2,
        "time": time.to_rfc3339(),
        "type_uid": 300201
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

struct Fixture {
    dir: tempfile::TempDir,
    parts: &'static LocalObjectStore,
    sources: LocalObjectStore,
    /// (key, rows)
    objects: Vec<(String, usize)>,
}

/// [`fixture_spanning`] over [`SPAN_HOURS`] event hours.
fn fixture(wide: usize, rows_per_hour: usize, narrow: usize, narrow_rows: usize) -> Fixture {
    fixture_spanning(SPAN_HOURS, wide, rows_per_hour, narrow, narrow_rows)
}

/// `wide` objects whose rows spread over `span_hours` event hours
/// (`rows_per_hour` rows in every hour, the bakeoff's "spread" shape), then
/// `narrow` live objects of `narrow_rows` rows in the ingest hour.
fn fixture_spanning(span_hours: i64, wide: usize, rows_per_hour: usize, narrow: usize, narrow_rows: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let sources_dir = dir.path().join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let mut objects = Vec::new();
    let mut n = 0;
    for o in 0..wide {
        let events = (0..span_hours as usize * rows_per_hour).map(|r| {
            n += 1;
            let hour = (r / rows_per_hour) as i64;
            // Each object's rows sit at distinct seconds of every hour.
            let time = DAY0_S + hour * 3_600 + ((o * rows_per_hour + r % rows_per_hour) % 3_600) as i64;
            event(&format!("w-{o:05}-{r:05}"), time, n)
        }).collect::<Vec<_>>();
        let key = format!("bronze/w-{o:05}.parquet");
        write_bronze(&sources_dir.join(&key), &events);
        objects.push((key, events.len()));
    }
    for o in 0..narrow {
        let events = (0..narrow_rows).map(|r| {
            n += 1;
            event(&format!("n-{o:05}-{r:05}"), NOW_MS / 1_000 - 30 + (r as i64 % 20), n)
        }).collect::<Vec<_>>();
        let key = format!("bronze/n-{o:05}.parquet");
        write_bronze(&sources_dir.join(&key), &events);
        objects.push((key, events.len()));
    }
    let parts: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("parts")).unwrap()));
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    Fixture { dir, parts, sources, objects }
}

fn notice(key: &str, notified_ms: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
        notified_at_ms: notified_ms,
    }
}

/// The spool, checking custody on every ack: each acked source must already
/// be consumed by a committed `add`, and each is acked exactly once.
/// `fail_ack_at` (1-based) fails that ack call once, after the `add` landed:
/// the crash between the log commit and the ack.
struct CheckedQueue<'a> {
    spool: SpoolQueue,
    parts: &'a LocalObjectStore,
    sources: &'a LocalObjectStore,
    keys: std::sync::Mutex<BTreeMap<String, String>>,
    acked: std::sync::Mutex<HashSet<String>>,
    ack_calls: AtomicUsize,
    fail_ack_at: AtomicUsize,
}

impl<'a> CheckedQueue<'a> {
    fn new(fx: &'a Fixture) -> Self {
        Self {
            spool: SpoolQueue::new(fx.dir.path().join("spool"), TENANT).unwrap(),
            parts: fx.parts,
            sources: &fx.sources,
            keys: Default::default(),
            acked: Default::default(),
            ack_calls: AtomicUsize::new(0),
            fail_ack_at: AtomicUsize::new(usize::MAX),
        }
    }
}

#[async_trait]
impl NoticeQueue for CheckedQueue<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let pending = self.spool.pending(max).await?;
        let mut keys = self.keys.lock().unwrap();
        for (handle, notice) in &pending {
            keys.insert(handle.0.clone(), notice.key.clone());
        }
        Ok(pending)
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        let call = self.ack_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_ack_at.load(Ordering::SeqCst) {
            anyhow::bail!("injected: the process dies after the add, before the ack");
        }
        let live = load_log(self.parts, TENANT).await?;
        for handle in handles {
            let key = self.keys.lock().unwrap().get(&handle.0).cloned().expect("acked handle was pending");
            let bytes = self.sources.get(&key).await?.expect("source object");
            let source = SourceRef { key: key.clone(), version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "CUSTODY: {key} acked before its add committed");
            anyhow::ensure!(self.acked.lock().unwrap().insert(key.clone()), "{key} acked twice");
        }
        self.spool.ack(handles).await
    }
    /// Here only crash replays are skipped (no refusals): each must be a
    /// source a committed `add` already consumed, its rows all duplicates.
    async fn ack_skipped(&self, acks: &[(NoticeHandle, AckCounts)]) -> Result<()> {
        let live = load_log(self.parts, TENANT).await?;
        for (handle, counts) in acks {
            let key = self.keys.lock().unwrap().get(&handle.0).cloned().expect("skipped handle was pending");
            let bytes = self.sources.get(&key).await?.expect("source object");
            let source = SourceRef { key: key.clone(), version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "CUSTODY: {key} skipped but never consumed");
            anyhow::ensure!(counts.rows_duplicate == counts.rows && counts.rows_rejected == 0, "{key}: a replay is all duplicates");
            anyhow::ensure!(self.acked.lock().unwrap().insert(key.clone()), "{key} acked twice");
        }
        let handles = acks.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>();
        self.spool.ack(&handles).await
    }
}

static SIGNER: std::sync::OnceLock<LocalPartSigner> = std::sync::OnceLock::new();

fn signer() -> &'static LocalPartSigner {
    SIGNER.get_or_init(|| LocalPartSigner::new("lab-signer-4674", SigningKey::from_bytes(&[46; 32])).unwrap())
}

/// The cell's ingest settings that matter here (`part_ingest/cell.rs`):
/// background merges, the production flush policy and admission group.
/// Prevalence is off (its local state is not under test).
fn config(fx: &Fixture) -> IngestConfig {
    let mut cfg = IngestConfig::new(TENANT, fx.dir.path().join("work"));
    cfg.background_merges = true;
    cfg.prevalence_enabled = false;
    cfg
}

async fn open<'a>(fx: &'a Fixture, queue: &'a CheckedQueue<'a>, now_ms: i64) -> Ingestor<'a> {
    let mut ingestor = Ingestor::open(config(fx), fx.parts, &fx.sources, queue, signer(), signer().trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    ingestor.set_background_store(fx.parts);
    ingestor.set_background_signer(signer());
    ingestor
}

/// Tick like the cell loop (1 s of clock per tick) until every notice is
/// acknowledged and nothing is buffered or in flight.
async fn drain(ingestor: &mut Ingestor<'_>, queue: &CheckedQueue<'_>, mut clock: i64) -> Result<i64> {
    for _ in 0..2_000 {
        ingestor.tick(clock).await?;
        let health = ingestor.health();
        if queue.spool.pending(1).await?.is_empty() && health.buffered_rows == 0 && health.flushes_in_flight == 0 {
            return Ok(clock);
        }
        clock += 1_000;
        tokio::task::yield_now().await;
    }
    panic!("the backlog never drained");
}

/// Every `add` entry's L0 parts: (hour, rows) per part, per entry.
async fn added_l0_parts(parts: &LocalObjectStore) -> Vec<Vec<(i32, u64)>> {
    let keys = LogKeys::new(TENANT).unwrap();
    let mut adds = Vec::new();
    for seq in 0.. {
        let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { parts, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            adds.push(parts.iter().filter(|p| p.level == Level::L0).map(|p| (p.event_hour, p.rows)).collect());
        }
    }
    adds
}

async fn consumed_per_add(parts: &LocalObjectStore) -> Vec<Vec<String>> {
    let keys = LogKeys::new(TENANT).unwrap();
    let mut adds = Vec::new();
    for seq in 0.. {
        let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            adds.push(consumed.into_iter().map(|source| source.key).collect());
        }
    }
    adds
}

/// Every uid in the live set, read back from the part store.
async fn live_uids(parts: &LocalObjectStore) -> Vec<String> {
    let set = load_log(parts, TENANT).await.unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut uids = Vec::new();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let path = scratch.path().join(format!("{}-{index}.parquet", part.part_id));
            std::fs::write(&path, parts.get(&keys.data(index)).await.unwrap().unwrap()).unwrap();
            uids.extend(read_time_uids(&path).unwrap().into_iter().map(|(_, uid)| uid));
        }
    }
    uids
}

/// Exactly once: every source consumed by one `add`, every notice acked
/// once after it, every row in the live set once.
async fn assert_exactly_once(fx: &Fixture, queue: &CheckedQueue<'_>) {
    let mut consumed = HashSet::new();
    for key in consumed_per_add(fx.parts).await.into_iter().flatten() {
        assert!(consumed.insert(key.clone()), "{key} consumed by two adds");
    }
    assert_eq!(consumed.len(), fx.objects.len(), "every source consumed once");
    assert_eq!(queue.acked.lock().unwrap().len(), fx.objects.len(), "every notice acked once");
    let uids = live_uids(fx.parts).await;
    let unique = uids.iter().collect::<HashSet<_>>();
    assert_eq!(unique.len(), uids.len(), "a uid appears twice in the live set");
    assert_eq!(uids.len(), fx.objects.iter().map(|(_, rows)| rows).sum::<usize>(), "rows lost or gained");
}

/// THE REGRESSION. A backlog of objects that each spread over 166 event
/// hours (one row per hour per object) is pulled while ingest is behind.
/// Before NAN-4674 every flush sealed after ONE admission group (the 48-hour
/// cap): at most `max_objects_per_admission` (64) objects, so each hour's L0
/// part held at most 64 rows and every hour got one part per group. Now the
/// buffer keeps admitting groups to its row/byte/object caps: each `add`
/// writes one large part per hour, every hour gets a bounded number of parts,
/// and custody (each source in one `add`, acks after it) is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wide_backfill_coalesces_into_a_bounded_number_of_large_parts_per_hour() {
    const OBJECTS: usize = 300;
    let fx = fixture(OBJECTS, 1, 0, 0);
    let queue = CheckedQueue::new(&fx);
    // The backlog landed a while ago: ingest is behind from the first tick.
    for (key, _) in &fx.objects {
        queue.spool.deliver(&notice(key, NOW_MS - 20 * 60_000)).unwrap();
    }
    let mut ingestor = open(&fx, &queue, NOW_MS).await;
    let group = config(&fx).max_objects_per_admission;
    drain(&mut ingestor, &queue, NOW_MS).await.unwrap();
    let health = ingestor.health().clone();
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;

    let adds = added_l0_parts(fx.parts).await;
    let parts = adds.iter().flatten().collect::<Vec<_>>();
    let rows = parts.iter().map(|(_, rows)| rows).sum::<u64>();
    assert_eq!(rows as usize, OBJECTS * SPAN_HOURS as usize);
    let mut per_hour: BTreeMap<i32, usize> = BTreeMap::new();
    for (hour, _) in &parts {
        *per_hour.entry(*hour).or_default() += 1;
    }
    let max_per_hour = per_hour.values().copied().max().unwrap();
    let mean_rows = rows as f64 / parts.len() as f64;
    eprintln!("NAN4674 adds={} l0_parts={} hours={} max_l0_per_hour={max_per_hour} mean_rows_per_l0={mean_rows:.0} \
        live_max_parts_per_hour={} (one group per flush would be >= {} adds, <= {group} rows per part)",
        adds.len(), parts.len(), per_hour.len(), health.max_parts_per_hour, OBJECTS.div_ceil(group));
    assert_eq!(per_hour.len(), SPAN_HOURS as usize);
    assert!(adds.iter().all(|add| {
        let hours = add.iter().map(|(hour, _)| hour).collect::<HashSet<_>>();
        hours.len() == add.len()
    }), "below 16,384 rows an hour is one L0 part per add");
    assert!(adds.len() < OBJECTS.div_ceil(group), "flushes coalesce admission groups: {} adds", adds.len());
    assert!(max_per_hour <= 3, "bounded L0 parts per hour: {max_per_hour}");
    assert!(mean_rows > group as f64, "parts larger than one admission group's rows: {mean_rows:.0}");
    assert!(health.max_parts_per_hour <= 3 && health.max_parts_per_hour < FRAGMENTED_HOUR_PARTS);
}

/// One object spanning 166 hours is one part per hour, behind or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_object_spanning_166_hours_writes_one_part_per_hour() {
    let fx = fixture(1, 3, 0, 0);
    let queue = CheckedQueue::new(&fx);
    queue.spool.deliver(&notice(&fx.objects[0].0, NOW_MS)).unwrap();
    let mut ingestor = open(&fx, &queue, NOW_MS).await;
    drain(&mut ingestor, &queue, NOW_MS).await.unwrap();
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;
    let adds = added_l0_parts(fx.parts).await;
    assert_eq!(adds.len(), 1);
    assert_eq!(adds[0].len(), SPAN_HOURS as usize);
    assert!(adds[0].iter().all(|(_, rows)| *rows == 3));
}

/// The live lane is untouched. Not behind (the steady state), a narrow
/// live object commits exactly at the production flush age (10 s), not
/// before; a wide object that is not part of a backlog still seals at the
/// 48-hour cap the tick it is admitted, as before NAN-4674.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_lane_seals_exactly_as_before() {
    assert_eq!(flush_event_hour_cap(false), MAX_FLUSH_EVENT_HOURS);
    assert_eq!(MAX_FLUSH_EVENT_HOURS, 48);
    assert!(flush_event_hour_cap(true) > MAX_FLUSH_EVENT_HOURS);

    let fx = fixture(0, 0, 1, 5);
    let queue = CheckedQueue::new(&fx);
    let mut ingestor = open(&fx, &queue, NOW_MS).await;
    queue.spool.deliver(&notice(&fx.objects[0].0, NOW_MS)).unwrap();
    let first = ingestor.tick(NOW_MS).await.unwrap();
    assert_eq!((first.admitted_rows, first.flushed_parts), (5, 0));
    for elapsed in [1_000, 5_000, 9_999] {
        ingestor.tick(NOW_MS + elapsed).await.unwrap();
        assert!(queue.acked.lock().unwrap().is_empty(), "flushed early at +{elapsed} ms");
    }
    let sealed = drain(&mut ingestor, &queue, NOW_MS + 10_000).await.unwrap();
    assert!(sealed - NOW_MS <= 11_000, "the live part landed {} ms after admission", sealed - NOW_MS);
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;

    // Not behind, a 166-hour object seals at once (the 48-hour rule).
    let fx = fixture(1, 1, 0, 0);
    let queue = CheckedQueue::new(&fx);
    let mut ingestor = open(&fx, &queue, NOW_MS).await;
    queue.spool.deliver(&notice(&fx.objects[0].0, NOW_MS)).unwrap();
    let report = ingestor.tick(NOW_MS).await.unwrap();
    assert_eq!(report.admitted_rows, SPAN_HOURS as u64);
    drain(&mut ingestor, &queue, NOW_MS).await.unwrap();
    assert_eq!(ingestor.health().buffered_rows, 0);
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;
}

/// A live object queued behind a wide backfill commits within the catch-up
/// age bound it had before NAN-4674 (30 s plus the flights ahead of it):
/// widening only lifts the hour cap, never the age.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_object_behind_a_wide_backfill_keeps_the_catch_up_age_bound() {
    let fx = fixture(200, 1, 1, 5);
    let queue = CheckedQueue::new(&fx);
    for (key, _) in &fx.objects {
        queue.spool.deliver(&notice(key, NOW_MS - 20 * 60_000)).unwrap();
    }
    let live_key = fx.objects.last().unwrap().0.clone();
    let mut ingestor = open(&fx, &queue, NOW_MS).await;
    let mut clock = NOW_MS;
    let mut admitted_at = None;
    let mut acked_at = None;
    for _ in 0..600 {
        ingestor.tick(clock).await.unwrap();
        let pending = queue.spool.pending(10_000).await.unwrap();
        let waiting = pending.iter().any(|(_, notice)| notice.key == live_key);
        if admitted_at.is_none() && ingestor.health().buffered_rows > 0 && waiting {
            // Still pending (unacked) while buffered or queued; note the
            // first tick it could have been admitted.
            admitted_at.get_or_insert(clock);
        }
        if !waiting && queue.acked.lock().unwrap().contains(&live_key) {
            acked_at = Some(clock);
            break;
        }
        clock += 1_000;
        tokio::task::yield_now().await;
    }
    let acked_at = acked_at.expect("the live object committed");
    assert!(acked_at - NOW_MS <= 60_000, "the live object took {} ms behind the backfill", acked_at - NOW_MS);
    drain(&mut ingestor, &queue, clock).await.unwrap();
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;
}

/// Custody under a crash. The wide buffer's `add` commits, then the process
/// dies before the ack: on reopen every source of that buffer is
/// redelivered, recognised as consumed and acked without a second copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_between_a_wide_add_and_its_ack_replays_exactly_once() {
    let fx = fixture(150, 1, 0, 0);
    let queue = CheckedQueue::new(&fx);
    for (key, _) in &fx.objects {
        queue.spool.deliver(&notice(key, NOW_MS - 20 * 60_000)).unwrap();
    }
    queue.fail_ack_at.store(1, Ordering::SeqCst);
    let mut clock = NOW_MS;
    {
        let mut ingestor = open(&fx, &queue, clock).await;
        let mut crashed = false;
        for _ in 0..200 {
            if ingestor.tick(clock).await.is_err() {
                crashed = true;
                break;
            }
            clock += 1_000;
        }
        assert!(crashed, "the injected ack failure fired");
        assert!(!consumed_per_add(fx.parts).await.is_empty(), "the add committed before the crash");
        assert!(queue.acked.lock().unwrap().is_empty());
    }
    queue.fail_ack_at.store(usize::MAX, Ordering::SeqCst);
    let mut ingestor = open(&fx, &queue, clock).await;
    drain(&mut ingestor, &queue, clock).await.unwrap();
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;
}

/// The tiny-batch fold keeps every row in order, never touches live-sized
/// batches or a run under [`TINY_BATCH_RUN`], never merges across a schema
/// change, and frees the per-array overhead it is for.
#[test]
fn tiny_batches_fold_without_changing_rows() {
    use arrow_array::{ArrayRef, Int64Array, StringArray};
    let schema = Arc::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("time", arrow_schema::DataType::Int64, false),
        arrow_schema::Field::new("uid", arrow_schema::DataType::Utf8, false),
    ]));
    let batch = |schema: &Arc<arrow_schema::Schema>, from: i64, rows: usize| arrow_array::RecordBatch::try_new(schema.clone(), vec![
        Arc::new(Int64Array::from_iter_values(from..from + rows as i64)) as ArrayRef,
        Arc::new(StringArray::from_iter_values((0..rows).map(|r| format!("u{}", from + r as i64)))) as ArrayRef,
    ]).unwrap();
    let rows = |batches: &[arrow_array::RecordBatch]| batches.iter().flat_map(|b| {
        let t = b.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
        (0..b.num_rows()).map(|i| t.value(i)).collect::<Vec<_>>()
    }).collect::<Vec<_>>();
    // A live-sized batch, then tiny ones: nothing folds below the run.
    let mut batches = vec![batch(&schema, 0, TINY_BATCH_ROWS)];
    for i in 0..TINY_BATCH_RUN - 1 {
        batches.push(batch(&schema, 10_000 + i as i64, 1));
        assert_eq!(compact_tiny_batches(&mut batches).unwrap(), (0, 0));
    }
    let before = rows(&batches);
    let bytes_before = batches.iter().map(|b| b.get_array_memory_size() as u64).sum::<u64>();
    let last = batch(&schema, 20_000, 1);
    let last_bytes = last.get_array_memory_size() as u64;
    batches.push(last);
    let (freed, added) = compact_tiny_batches(&mut batches).unwrap();
    assert_eq!(batches.len(), 2, "the live batch stays, the run of {TINY_BATCH_RUN} folds into one");
    assert_eq!(batches[0].num_rows(), TINY_BATCH_ROWS);
    assert_eq!(rows(&batches), [before, vec![20_000]].concat(), "same rows, same order");
    assert!(added < freed, "folding frees the per-array overhead ({freed} -> {added})");
    let bytes_after = batches.iter().map(|b| b.get_array_memory_size() as u64).sum::<u64>();
    assert_eq!(bytes_after + freed, bytes_before + last_bytes + added, "the byte delta is exact");
    // A schema change ends the run: tiny batches under another schema
    // never fold with the earlier ones.
    let other = Arc::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("time", arrow_schema::DataType::Int64, false),
        arrow_schema::Field::new("uid", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("extra", arrow_schema::DataType::Utf8, true),
    ]));
    let mut mixed = (0..TINY_BATCH_RUN / 2).map(|i| batch(&schema, i as i64, 1)).collect::<Vec<_>>();
    for i in 0..TINY_BATCH_RUN / 2 {
        mixed.push(arrow_array::RecordBatch::try_new(other.clone(), vec![
            Arc::new(Int64Array::from(vec![100 + i as i64])) as ArrayRef,
            Arc::new(StringArray::from(vec!["x"])) as ArrayRef,
            Arc::new(StringArray::from(vec![None::<&str>])) as ArrayRef,
        ]).unwrap());
        assert_eq!(compact_tiny_batches(&mut mixed).unwrap(), (0, 0));
    }
    assert_eq!(mixed.len(), TINY_BATCH_RUN);
}


/// Review of NAN-4674: the fold must actually run on the production
/// admission path, not only in the unit test above. One object per
/// admission (a memory-bounded group of one) adds one tiny batch per hour
/// per tick; a wide buffer collects more than [`TINY_BATCH_RUN`] of them
/// per hour before its catch-up age seals it. Every row lands exactly once:
/// a fold that kept the old batches (duplicating their rows) fails here,
/// since nothing between the buffer and the L0 part drops a repeated
/// `(time, uid)` (`sorted_hour` only concatenates and sorts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fold_runs_on_the_admission_path_and_keeps_every_row_once() {
    const OBJECTS: usize = 2 * TINY_BATCH_RUN;
    let fx = fixture_spanning(24, OBJECTS, 1, 0, 0);
    let queue = CheckedQueue::new(&fx);
    for (key, _) in &fx.objects {
        queue.spool.deliver(&notice(key, NOW_MS - 20 * 60_000)).unwrap();
    }
    let mut cfg = config(&fx);
    cfg.max_objects_per_admission = 1;
    let mut ingestor = Ingestor::open(cfg, fx.parts, &fx.sources, &queue, signer(), signer().trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), NOW_MS).await.unwrap();
    ingestor.set_background_store(fx.parts);
    ingestor.set_background_signer(signer());
    // 200 ms of clock per tick: the whole backlog is admitted well inside
    // the 30 s catch-up age, one object per tick.
    let mut clock = NOW_MS;
    for _ in 0..OBJECTS + 2 {
        ingestor.tick(clock).await.unwrap();
        clock += 200;
    }
    assert!(ingestor.health().tiny_batch_folds_total > 0, "the fold never ran on the admission path");
    drain(&mut ingestor, &queue, clock).await.unwrap();
    drop(ingestor);
    assert_exactly_once(&fx, &queue).await;
    let adds = added_l0_parts(fx.parts).await;
    let rows = adds.iter().flatten().map(|(_, rows)| rows).sum::<u64>();
    assert_eq!(rows as usize, OBJECTS * 24, "the L0 parts hold every row once");
}

/// Review of NAN-4674: part counts ACROSS flushes. A sustained backfill
/// whose every flush covers the same sealed hours adds one L0 part to each
/// of them per flush, for as long as the backlog lasts (ingest is behind the
/// whole time, so ordinary history merges wait). Here every flush is one
/// admission (a 1 s seal; a seal waits beside an unfinished flight, so a
/// flush holds a few objects), ~100+ flushes over the same 8 hours.
///
/// - Production policy: the minute lane keeps every hour well under the
///   fragmented bound.
/// - Minute lane unable to keep up (its triggers disabled, the worst case):
///   hours reach [`FRAGMENTED_HOUR_PARTS`] and their `h` merges launch WHILE
///   ingest is still behind, so no hour ever reaches the signal's warn
///   level (128).
///
/// Rows, uids and custody stay exact either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_backfill_flushes_over_the_same_hours_stay_bounded() {
    const OBJECTS: usize = 600;
    const SPAN: i64 = 8;
    let stalled = MergePolicy { minute_min_l0_parts: usize::MAX, minute_max_l0_age_ms: i64::MAX, ..MergePolicy::default() };
    for (name, policy) in [("production", MergePolicy::default()), ("minute lane stalled", stalled)] {
        let fx = fixture_spanning(SPAN, OBJECTS, 2, 0, 0);
        let queue = CheckedQueue::new(&fx);
        for (key, _) in &fx.objects {
            queue.spool.deliver(&notice(key, NOW_MS - 20 * 60_000)).unwrap();
        }
        let mut cfg = config(&fx);
        cfg.max_objects_per_admission = 1;
        cfg.flush_interval_override_ms = Some(1_000);
        cfg.merge_policy = policy;
        let mut ingestor = Ingestor::open(cfg, fx.parts, &fx.sources, &queue, signer(), signer().trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), NOW_MS).await.unwrap();
        ingestor.set_background_store(fx.parts);
        ingestor.set_background_signer(signer());
        let mut clock = NOW_MS;
        let mut worst = 0;
        let mut h_parts_while_behind = 0;
        let mut drained = false;
        for _ in 0..4_000 {
            ingestor.tick(clock).await.unwrap();
            let health = ingestor.health().clone();
            worst = worst.max(health.max_parts_per_hour);
            let behind = !queue.spool.pending(1).await.unwrap().is_empty();
            if behind {
                let set = load_log(fx.parts, TENANT).await.unwrap();
                h_parts_while_behind = h_parts_while_behind.max(set.parts().filter(|p| p.level == Level::Hour).count());
            } else if health.buffered_rows == 0 && health.flushes_in_flight == 0 {
                drained = true;
                break;
            }
            clock += 1_000;
            tokio::task::yield_now().await;
        }
        assert!(drained, "{name}: the backlog never drained");
        let adds = added_l0_parts(fx.parts).await;
        let mut l0_per_hour: BTreeMap<i32, usize> = BTreeMap::new();
        for (hour, _) in adds.iter().flatten() {
            *l0_per_hour.entry(*hour).or_default() += 1;
        }
        let most_l0 = l0_per_hour.values().copied().max().unwrap();
        eprintln!("NAN4674 repeated[{name}]: adds={} l0_per_hour_max={most_l0} live_max_parts_per_hour_peak={worst} \
            h_parts_while_behind={h_parts_while_behind}", adds.len());
        assert!(most_l0 > FRAGMENTED_HOUR_PARTS + 16, "{name}: the shape must feed each hour past the bound ({most_l0})");
        drop(ingestor);
        assert_exactly_once(&fx, &queue).await;
        if name == "production" {
            assert!(worst < FRAGMENTED_HOUR_PARTS, "{name}: the minute lane bounds every hour ({worst})");
        } else {
            assert!(h_parts_while_behind > 0, "{name}: fragmented-hour merges must launch while ingest is behind");
            assert!(worst < 2 * FRAGMENTED_HOUR_PARTS, "{name}: fragmented merges keep up ({worst} parts in an hour)");
        }
    }
}
