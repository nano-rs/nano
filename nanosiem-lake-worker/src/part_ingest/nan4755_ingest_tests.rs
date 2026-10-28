// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4755 on a real ingestor: a catch-up backlog that leaves a sealed
//! hour in many parts, under a memory limit too small for its merge at full
//! size, drains without an OOM and without a restart.
//!
//! FP cell-us-1, 2026-10-28: after a one-hour stall the ops tenant's ingest
//! role (memory.max 3.4 GB) was OOM-killed 20-40 s into every start by the
//! `h` merge of the stall hour (33 inputs). Nothing bounded that merge by the
//! role's limit and nothing remembered it across the kill, so every restart
//! ran it again at the same size.
//!
//! Here the merge runs through the production scheduler (background lanes,
//! the static part store and signer), with the memory guard reading the
//! test heap of the threads under test in place of the cgroup.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::merge_attempts::{merge_id, MergeAttempts};
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};

const TENANT: &str = "47550000-0000-4000-8000-000000000001";
/// The backlog's event hour.
const HOUR: i64 = 492_096;
/// Ingest runs ten minutes into the hour (the backlog arriving) ...
const INGEST_CLOCK: i64 = HOUR * 3_600_000 + 600_000;
/// ... and the sealed hour merges once ingest is past it.
const MERGE_CLOCK: i64 = (HOUR + 2) * 3_600_000;
const OBJECTS: usize = 24;
const ROWS_PER_OBJECT: usize = 1_000;

/// A catch-up row: wide (~1.5 KB raw), varied hosts and users.
fn event(i: usize) -> Value {
    // Within the first ten minutes of the hour: never ahead of the clock.
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(HOUR * 3_600 + (i as i64 * 7) % 590, 0).unwrap();
    // The seed schema's class (other classes are refused by it here).
    let (class_uid, class_name, category_name, source) = (3002, "Authentication", "Identity & Access Management", "WINDOWS_EVENT");
    let uid = format!("nan4755-{i:07}");
    let raw = format!("<raw id='{i}'>{}</raw>", "r".repeat(600 + i % 17));
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 23)}},
        "category_name": category_name, "category_uid": class_uid / 1000,
        "class_name": class_name, "class_uid": class_uid,
        "message": format!("{class_name} {i} {}", "m".repeat(400 + i % 13)), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "catch-up", "log_source": source,
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.{}.{}.{}", i % 3, i % 200, i % 250), "hostname": format!("ws-{}.corp.local", i % 41)},
        "dst_endpoint": {"ip": format!("192.168.{}.{}", i % 5, i % 20)},
        "user": {"name": format!("user{}", i % 23), "uid": format!("S-1-5-21-{}", i % 23)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": class_uid * 100 + 1
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

/// The limit the guard sees (0: none) and the heap counted as "in use"
/// above `BASE` (the merge phase's start): the test's `memory.max`.
static LIMIT: AtomicU64 = AtomicU64::new(0);
static BASE: AtomicIsize = AtomicIsize::new(0);

fn heap_probe() -> Option<(u64, u64)> {
    let limit = LIMIT.load(Ordering::SeqCst);
    (limit > 0).then(|| ((crate::test_heap::live() - BASE.load(Ordering::SeqCst)).max(0) as u64, limit))
}

struct Lab {
    _root: tempfile::TempDir,
    root: std::path::PathBuf,
    parts: &'static LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    signer: &'static LocalPartSigner,
}

impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
        Self {
            parts: Box::leak(Box::new(LocalObjectStore::new(root.join("parts")).unwrap())),
            sources: LocalObjectStore::new(root.join("sources")).unwrap(),
            spool: SpoolQueue::new(root.join("spool"), TENANT).unwrap(),
            signer: Box::leak(Box::new(LocalPartSigner::new("lab-signer-nan4755", ed25519_dalek::SigningKey::from_bytes(&[55; 32])).unwrap())),
            _root: dir,
            root,
        }
    }

    fn config(&self) -> IngestConfig {
        let mut config = IngestConfig::new(TENANT, self.root.join("work"));
        config.prevalence_enabled = false;
        config.background_merges = true;
        // The backlog lands as one L0 part per object, all in one hour: no
        // minute merge consolidates them first (the stall hour on FP was
        // 33 parts when its `h` merge started).
        config.merge_policy.minute_min_l0_parts = usize::MAX;
        config.merge_policy.minute_max_l0_age_ms = i64::MAX / 4;
        config
    }

    async fn open(&self, now_ms: i64) -> Ingestor<'_> {
        let mut ingestor = Ingestor::open(self.config(), self.parts, &self.sources, &self.spool as &dyn NoticeQueue, self.signer,
            self.signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
        ingestor.set_background_store(self.parts);
        ingestor.set_background_signer(self.signer);
        ingestor
    }

    fn land(&self, name: &str, events: &[Value], at: i64) {
        let key = format!("bronze/{name}.parquet");
        write_bronze(&self.root.join("sources").join(&key), events);
        self.spool.deliver(&notice(&key, at)).unwrap();
    }

    /// The backlog: [`OBJECTS`] objects of the stalled hour, each committed
    /// as its own L0 part.
    async fn land_backlog(&self) {
        let mut ingestor = self.open(INGEST_CLOCK).await;
        for object in 0..OBJECTS {
            let at = INGEST_CLOCK + object as i64 * 1_000;
            let first = object * ROWS_PER_OBJECT;
            self.land(&format!("backlog-{object:03}"), &(first..first + ROWS_PER_OBJECT).map(event).collect::<Vec<_>>(), at - 500);
            let report = ingestor.tick(at).await.unwrap();
            assert_eq!(report.admitted_rows, ROWS_PER_OBJECT as u64, "object {object}: {report:?} {:?}", ingestor.quarantine_entries());
            ingestor.flush_now(at + 1).await.unwrap();
        }
        let l0 = ingestor.live_parts().iter().filter(|part| part.level == Level::L0 && i64::from(part.event_hour) == HOUR).count();
        assert_eq!(l0, OBJECTS, "the backlog hour is one part per object");
    }
}

/// Land the backlog on its own runtime (untracked).
fn land(lab: &Lab) {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(lab.land_backlog());
}

fn hour_parts(ingestor: &Ingestor<'_>) -> Vec<PartRef> {
    ingestor.live_parts().into_iter().filter(|part| i64::from(part.event_hour) == HOUR).collect()
}

async fn settle_merges(ingestor: &Ingestor<'_>) {
    while ingestor.merge_in_flight.iter().any(|flight| !flight.handle.is_finished()) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

struct Run {
    /// Heap high-water mark above the merge phase's start.
    peak: isize,
    stops: u64,
    ticks: usize,
    fresh_rows_committed: u64,
}

/// The merge phase of a landed backlog at `shift` (the shape a previous
/// process's deaths left in the merge ledger) under `limit` (0: none).
/// Fresh objects keep arriving the whole time: ingest must keep running.
fn merge_phase(lab: &Lab, shift: u8, limit: u64) -> Run {
    let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let id = merge_id(Level::Hour.code(), HOUR as i32);
    if shift > 0 {
        let mut ledger = MergeAttempts::open(&lab.root.join("work"), MERGE_CLOCK);
        for _ in 0..shift {
            ledger.shrink(&id, MERGE_CLOCK, OBJECTS).unwrap();
        }
    }
    // Process-wide; another test may have sized it for its own cap.
    super::super::merge::set_memory_budget(0);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
        .on_thread_start(|| crate::test_heap::track_current_thread(true)).build().unwrap();
    crate::test_heap::track_current_thread(true);
    let run = runtime.block_on(async {
        let mut ingestor = lab.open(MERGE_CLOCK).await;
        assert_eq!(ingestor.merge_attempts.shift(&id), shift);
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(heap_probe));
        BASE.store(crate::test_heap::reset_peak(), Ordering::SeqCst);
        LIMIT.store(limit, Ordering::SeqCst);
        let (mut now, mut ticks, mut fresh) = (MERGE_CLOCK, 0, 0);
        while hour_parts(&ingestor).len() > 1 {
            ticks += 1;
            assert!(ticks <= 12, "the backlog hour never merged: {:?}", ingestor.merge_attempts.entry(&id));
            // Live data keeps arriving beside the merge (the next hour).
            let first = 1_000_000 + ticks * 50;
            lab.land(&format!("fresh-{ticks:03}"), &(first..first + 50).map(|i| {
                let mut event = event(i);
                event["time"] = json!(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now - 1_000).unwrap().to_rfc3339());
                event
            }).collect::<Vec<_>>(), now - 1_000);
            ingestor.tick(now).await.unwrap();
            ingestor.flush_now(now + 1).await.unwrap();
            fresh += 50;
            // An empty buffer: the history lane may start the hour merge.
            ingestor.tick(now + 2).await.unwrap();
            settle_merges(&ingestor).await;
            // Reap: commit it, or record the guard stop.
            ingestor.tick(now + 3).await.unwrap();
            // Past any quarantine backoff (60 s after a failed attempt).
            now += 61_000 << ticks.min(6);
        }
        LIMIT.store(0, Ordering::SeqCst);
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
        let peak = crate::test_heap::peak() - BASE.load(Ordering::SeqCst);
        let parts = hour_parts(&ingestor);
        assert_eq!((parts.len(), parts[0].level), (1, Level::Hour), "the hour sealed into one `h` part");
        assert_eq!(parts[0].rows, (OBJECTS * ROWS_PER_OBJECT) as u64, "every backlog row");
        assert_eq!(ingestor.merge_attempts.entry(&id), None, "the commit cleared the ledger");
        assert_eq!(ingestor.health().rows_committed_total, fresh, "every fresh row committed");
        Run { peak, stops: ingestor.health().merge_memory_stops_total, ticks, fresh_rows_committed: fresh }
    });
    crate::test_heap::track_current_thread(false);
    run
}

/// The incident, end to end: the backlog hour's merge at full size needs
/// more than the limit; at its smallest shape it fits. Under that limit
/// the guard stops the full-size attempt before the limit is reached, the
/// merge reruns smaller in the same process, the hour seals with every
/// row, and fresh data commits throughout. Before NAN-4755 nothing stopped
/// the merge short of the cgroup OOM, and every restart ran it again.
#[test]
fn a_backlog_hour_under_a_small_memory_limit_merges_without_an_oom() {
    // The two shapes' working sets, unbounded.
    let full = { let lab = Lab::new(); land(&lab); merge_phase(&lab, 0, 0) };
    let small = { let lab = Lab::new(); land(&lab); merge_phase(&lab, super::super::merge_attempts::MAX_SHIFT, 0) };
    eprintln!("NAN-4755: backlog-hour merge peak: full shape {} KiB, smallest shape {} KiB", full.peak >> 10, small.peak >> 10);
    assert_eq!((full.stops, small.stops), (0, 0), "no limit, no stop");
    assert!(small.peak * 4 < full.peak * 3, "the smallest shape must need clearly less: {} vs {} KiB", small.peak >> 10, full.peak >> 10);

    // memory.max between the two: the guard (at 85%) fires above the small
    // shape's peak and below the full shape's.
    let guard_at = (small.peak + full.peak) / 2;
    let limit = (guard_at as f64 / super::super::merge_quota::MEMORY_GUARD_SHARE) as u64;
    assert!((full.peak as u64) > limit / 100 * 85, "fixture: the full shape must not fit");
    let lab = Lab::new();
    land(&lab);
    let run = merge_phase(&lab, 0, limit);
    eprintln!("NAN-4755: under a {} KiB limit: peak {} KiB, {} guard stops, {} ticks", limit >> 10, run.peak >> 10, run.stops, run.ticks);
    assert!(run.stops >= 1, "the full-size attempt was stopped by the guard");
    assert!((run.peak as u64) < limit, "never reached the limit (no OOM): peak {} KiB, limit {} KiB", run.peak >> 10, limit >> 10);
    assert_eq!(run.fresh_rows_committed, run.ticks as u64 * 50, "ingest kept committing fresh data beside the merge");
}

struct Drained {
    /// Heap high-water mark above the phase's start.
    peak: isize,
    ticks: usize,
    entry: Option<super::super::merge_attempts::Entry>,
    parts: Vec<PartRef>,
    left_unmerged_gauge: u64,
    fresh: u64,
    rows_committed: u64,
}

/// NAN-4755 convergence: run the production scheduler under `limit` until
/// the backlog hour plans no more merges (converged into its final parts,
/// or left unmerged), with fresh data landing every tick. Panics if that
/// takes more than a bounded number of ticks: no retry loop.
fn drain_under(lab: &Lab, limit: u64) -> Drained {
    let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let id = merge_id(Level::Hour.code(), HOUR as i32);
    super::super::merge::set_memory_budget(0);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
        .on_thread_start(|| crate::test_heap::track_current_thread(true)).build().unwrap();
    crate::test_heap::track_current_thread(true);
    let drained = runtime.block_on(async {
        let mut ingestor = lab.open(MERGE_CLOCK).await;
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(heap_probe));
        BASE.store(crate::test_heap::reset_peak(), Ordering::SeqCst);
        LIMIT.store(limit, Ordering::SeqCst);
        let (mut now, mut ticks, mut fresh) = (MERGE_CLOCK, 0_usize, 0_u64);
        loop {
            ticks += 1;
            // 3 shape steps + 24 -> 12 -> 6 -> 3 -> 2 inputs (one chunk
            // failing per step) + 2 minimum-chunk failures, with slack for chunks that
            // commit between: never unbounded.
            assert!(ticks <= 40, "the backlog hour neither converged nor was left unmerged: {:?}", ingestor.merge_attempts.entry(&id));
            let first = 2_000_000 + ticks * 50;
            lab.land(&format!("fresh-{ticks:03}"), &(first..first + 50).map(|i| {
                let mut event = event(i);
                event["time"] = json!(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now - 1_000).unwrap().to_rfc3339());
                event
            }).collect::<Vec<_>>(), now - 1_000);
            ingestor.tick(now).await.unwrap();
            ingestor.flush_now(now + 1).await.unwrap();
            fresh += 50;
            ingestor.tick(now + 2).await.unwrap();
            settle_merges(&ingestor).await;
            ingestor.tick(now + 3).await.unwrap();
            let planned = plan_merges_with(&ingestor.live_parts(), now + 3, &ingestor.cfg.merge_policy, true);
            let pending = ingestor.converge_memory_bound_merges(planned).into_iter().filter(|m| i64::from(m.event_hour) == HOUR).count();
            if pending == 0 && !ingestor.merge_in_flight.iter().any(|flight| i64::from(flight.merge.event_hour) == HOUR) {
                break;
            }
            // Past the quarantine backoff and any park.
            let parked = ingestor.merge_attempts.parked_until(&id, now).unwrap_or(0);
            now = (now + 3_600_001).max(parked + 1);
        }
        // Stable: more ticks start nothing for the hour and change nothing.
        let settled = (ingestor.merge_attempts.entry(&id).cloned(), hour_parts(&ingestor).len());
        for extra in 1..=3_i64 {
            now += extra * super::super::merge_attempts::PARK_MAX_MS;
            ingestor.tick(now).await.unwrap();
            settle_merges(&ingestor).await;
            ingestor.tick(now + 1).await.unwrap();
        }
        assert_eq!((ingestor.merge_attempts.entry(&id).cloned(), hour_parts(&ingestor).len()), settled, "a settled hour stays settled: no retry");
        LIMIT.store(0, Ordering::SeqCst);
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
        let peak = crate::test_heap::peak() - BASE.load(Ordering::SeqCst);
        assert_backlog_readable(lab).await;
        let rows_committed = ingestor.health().rows_committed_total;
        drop(ingestor);
        let mut ingestor = lab.open(now + 1).await;
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(heap_probe));
        BASE.store(crate::test_heap::reset_peak(), Ordering::SeqCst);
        LIMIT.store(limit, Ordering::SeqCst);
        ingestor.tick(now + super::super::merge_attempts::PARK_MAX_MS + 2).await.unwrap();
        assert!(!ingestor.merge_in_flight.iter().any(|flight| i64::from(flight.merge.event_hour) == HOUR));
        assert_eq!((ingestor.merge_attempts.entry(&id).cloned(), hour_parts(&ingestor).len()), settled,
            "restart preserves the settled hour");
        LIMIT.store(0, Ordering::SeqCst);
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
        Drained {
            peak,
            ticks,
            entry: ingestor.merge_attempts.entry(&id).cloned(),
            parts: hour_parts(&ingestor),
            left_unmerged_gauge: ingestor.health().merges_left_unmerged,
            fresh,
            rows_committed,
        }
    });
    crate::test_heap::track_current_thread(false);
    drained
}

/// The coordinator's P1 (NAN-4755): when even the smallest shape of the
/// hour's merge cannot fit, catch-up must still end. Under a limit at half
/// the smallest shape's need, the hour splits into chunks that fit and
/// converges into several `h` parts holding every row. Under a tiny limit
/// nothing fits: in a bounded number of attempts the hour is left as its
/// live L0 parts (readable, counted in `merges_left_unmerged`), never
/// retried, while fresh data commits throughout.
#[test]
fn a_backlog_hour_that_cannot_fit_converges_or_is_left_unmerged_in_bounded_attempts() {
    let small = { let lab = Lab::new(); land(&lab); merge_phase(&lab, super::super::merge_attempts::MAX_SHIFT, 0) };
    let backlog_rows = (OBJECTS * ROWS_PER_OBJECT) as u64;

    let limit = (small.peak as f64 * 0.5 / super::super::merge_quota::MEMORY_GUARD_SHARE) as u64;
    let lab = Lab::new();
    land(&lab);
    let split = drain_under(&lab, limit);
    eprintln!("NAN-4755: smallest shape {} KiB; under {} KiB: {} ticks, peak {} KiB, entry {:?}, parts {:?}", small.peak >> 10, limit >> 10,
        split.ticks, split.peak >> 10, split.entry, split.parts.iter().map(|p| (p.level, p.rows)).collect::<Vec<_>>());
    assert_eq!(split.parts.iter().map(|p| p.rows).sum::<u64>(), backlog_rows, "every backlog row stays live");
    assert!(split.entry.as_ref().is_some_and(|entry| entry.max_inputs.is_some() && entry.left_unmerged_at_limit.is_none()),
        "the hour split and converged: {:?}", split.entry);
    assert!(split.parts.iter().filter(|p| p.level == Level::Hour).count() >= 2, "merged as chunks");
    assert!(split.parts.iter().filter(|p| p.level != Level::Hour).count() <= 1, "at most a lone leftover part");
    assert!((split.peak as u64) < limit, "no OOM: peak {} KiB, limit {} KiB", split.peak >> 10, limit >> 10);
    assert_eq!((split.left_unmerged_gauge, split.rows_committed), (0, split.fresh), "fresh data committed throughout");

    let lab = Lab::new();
    land(&lab);
    let tiny = drain_under(&lab, 64 << 10);
    eprintln!("NAN-4755: under 64 KiB: {} ticks, entry {:?}, {} parts", tiny.ticks, tiny.entry, tiny.parts.len());
    let entry = tiny.entry.expect("ledger entry");
    assert!(entry.left_unmerged_at_limit.is_some(), "nothing fits: left unmerged, {entry:?}");
    assert!(entry.failures as usize <= 3 + 4 + 2, "bounded attempts: {entry:?}");
    assert!(tiny.left_unmerged_gauge >= 1, "visible in health");
    assert_eq!(tiny.parts.iter().map(|p| p.rows).sum::<u64>(), backlog_rows, "readable as its unmerged parts");
    assert_eq!(tiny.rows_committed, tiny.fresh, "ingest healthy: fresh data committed throughout");
}

/// The kill path: a process that died during the merge (SIGKILL: its
/// ledger entry is still in flight) leaves the next process running that
/// merge one step smaller, and the death is not charged to the object that
/// process was admitting alone.
#[tokio::test(flavor = "current_thread")]
async fn a_restart_after_dying_in_a_merge_runs_it_smaller_and_charges_no_object() {
    use super::super::admission_attempts::{object_id, AdmissionAttempts};
    let lab = Lab::new();
    let work = lab.root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let id = merge_id(Level::Hour.code(), HOUR as i32);
    let object = object_id("bronze/suspect.parquet", "1");
    // The dead process: it charged an object admitted alone, and was killed
    // with the hour merge in flight.
    AdmissionAttempts::open(&work).begin([object.as_str()], true).unwrap();
    MergeAttempts::open(&work, MERGE_CLOCK).begin(&id, OBJECTS).unwrap();
    let ingestor = lab.open(MERGE_CLOCK).await;
    assert_eq!(ingestor.merge_attempts.shift(&id), 1, "the merge reruns one step smaller");
    assert_eq!(ingestor.admission_attempts.suspect(&object), Some(0), "the death is not charged to the object");
    drop(ingestor);
    // A death with no merge in flight is charged as before.
    AdmissionAttempts::open(&work).begin([object.as_str()], true).unwrap();
    let ingestor = lab.open(MERGE_CLOCK).await;
    assert_eq!(ingestor.admission_attempts.suspect(&object), Some(1));
    assert_eq!(ingestor.merge_attempts.shift(&id), 1, "nothing else changed");
}

/// Recovery writes the merge ledger, the admission ledger, then the merge
/// acknowledgement. A crash at either boundary must forgive exactly once.
#[tokio::test(flavor = "current_thread")]
async fn admission_forgiveness_survives_a_restart_between_ledger_writes() {
    use super::super::admission_attempts::{object_id, AdmissionAttempts};
    for after_forgiveness in [false, true] {
        let lab = Lab::new();
        let work = lab.root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let id = merge_id(Level::Hour.code(), HOUR as i32);
        let object = object_id("bronze/suspect.parquet", "1");
        AdmissionAttempts::open(&work).begin([object.as_str()], true).unwrap();
        MergeAttempts::open(&work, MERGE_CLOCK).begin(&id, OBJECTS).unwrap();
        // Recovery shrank the merge and persisted that it is no longer in
        // flight, but has not acknowledged the admission forgiveness yet.
        let recovery = MergeAttempts::open(&work, MERGE_CLOCK);
        assert!(recovery.died_during_merge());
        if after_forgiveness {
            assert_eq!(AdmissionAttempts::open(&work).forgive_last_process().unwrap(), 1);
        }
        drop(recovery); // interrupted recovery
        let ingestor = lab.open(MERGE_CLOCK).await;
        assert_eq!(ingestor.admission_attempts.suspect(&object), Some(0));
        assert_eq!(ingestor.merge_attempts.shift(&id), 1, "recovery itself is not another merge death");
        drop(ingestor);
        // The acknowledgement must survive too: a subsequent unrelated
        // death counts against admission rather than being forgiven again.
        AdmissionAttempts::open(&work).begin([object.as_str()], true).unwrap();
        let ingestor = lab.open(MERGE_CLOCK).await;
        assert_eq!(ingestor.admission_attempts.suspect(&object), Some(1));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_merge_waits_for_a_durable_start_while_fresh_ingest_commits() {
    let lab = Lab::new();
    let mut ingestor = lab.open(INGEST_CLOCK).await;
    for object in 0..2 {
        lab.land(&format!("backlog-{object}"), &[event(object)], INGEST_CLOCK - 1);
        ingestor.tick(INGEST_CLOCK + object as i64).await.unwrap();
        ingestor.flush_now(INGEST_CLOCK + object as i64).await.unwrap();
    }
    assert_eq!(hour_parts(&ingestor).len(), 2);
    // File::create fails deterministically, including when tests run as root.
    let blocked = lab.root.join("work/merge-attempts.json.tmp");
    std::fs::create_dir(&blocked).unwrap();
    lab.land("fresh", &[{
        let mut row = event(99);
        row["time"] = json!(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(MERGE_CLOCK - 1_000).unwrap().to_rfc3339());
        row
    }], MERGE_CLOCK - 1);
    ingestor.tick(MERGE_CLOCK).await.unwrap();
    ingestor.flush_now(MERGE_CLOCK + 1).await.unwrap();
    ingestor.tick(MERGE_CLOCK + 2).await.unwrap();
    assert!(ingestor.merge_in_flight.is_empty(), "no unrecorded task may launch");
    assert!(ingestor.health().merge_failures_total > 0);
    assert_eq!(ingestor.health().rows_committed_total, 3, "admission is independent of the ledger failure");
    assert_eq!(hour_parts(&ingestor).len(), 2);
    std::fs::remove_dir(blocked).unwrap();
    ingestor.tick(MERGE_CLOCK + 120_000).await.unwrap();
    settle_merges(&ingestor).await;
    ingestor.tick(MERGE_CLOCK + 120_001).await.unwrap();
    assert_eq!(hour_parts(&ingestor).len(), 1, "compaction resumes after the recording failure clears");
}

/// The production reader's verified log selection, signed provenance and
/// Parquet payloads must expose each backlog uid exactly once, even with a
/// mixture of committed chunks and unmerged L0/M parts. A metadata row sum
/// alone could hide a duplicated row replacing a missing one.
async fn assert_backlog_readable(lab: &Lab) {
    use crate::part_query::log_view::PartLogView;
    use crate::parts::format::PartKeys;
    use crate::parts::provenance::SignedProvenance;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let view = PartLogView::open(lab.parts, TENANT, lab.signer.trusted()).await.unwrap();
    let selected = view.parts_overlapping(HOUR * 3_600_000_000, (HOUR + 1) * 3_600_000_000 - 1);
    let mut actual = Vec::new();
    for part in selected {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let bytes = lab.parts.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&bytes, TENANT, &lab.signer.trusted()).unwrap();
        for data in &signed.record.files.data {
            let bytes = lab.parts.get(&keys.file(&data.name)).await.unwrap().unwrap();
            for batch in ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes)).unwrap().build().unwrap() {
                actual.extend(super::super::writer::uid_strings(&batch.unwrap()).unwrap().iter().flatten().map(str::to_owned));
            }
        }
    }
    actual.sort();
    let expected = (0..OBJECTS * ROWS_PER_OBJECT).map(|i| format!("nan4755-{i:07}")).collect::<Vec<_>>();
    assert_eq!(actual, expected, "every backlog uid is readable exactly once");
}

/// Interrupt both sides of the part-log commit. Before append an uploaded
/// output is an orphan; after append its inputs are atomically superseded.
/// Restart before acknowledging the attempt must preserve earlier chunks,
/// never re-merge them, and still finish the remaining chunks/odd L0.
#[tokio::test(flavor = "current_thread")]
async fn split_chunk_commits_and_restarts_preserve_exactly_the_live_rows() {
    for after_append in [false, true] {
        let lab = Lab::new();
        lab.land_backlog().await;
        let id = merge_id(Level::Hour.code(), HOUR as i32);
        let work = lab.root.join("work");
        let mut ledger = MergeAttempts::open(&work, MERGE_CLOCK);
        for _ in 0..=super::super::merge_attempts::MAX_SHIFT {
            ledger.shrink(&id, MERGE_CLOCK, 6).unwrap();
        }
        assert_eq!(ledger.max_inputs(&id), Some(3));
        let mut ingestor = lab.open(MERGE_CLOCK).await;
        let plan = plan_merges_with(&ingestor.live_parts(), MERGE_CLOCK, &ingestor.cfg.merge_policy, true);
        let chunk = ingestor.converge_memory_bound_merges(plan).remove(0);
        let flight = ingestor.spawn_merge(chunk, MERGE_CLOCK).await.unwrap();
        let (result, published) = flight.handle.await.unwrap().unwrap();
        let output_id = published.as_ref().unwrap().part_id.clone();
        if after_append {
            ingestor.commit_merge(flight.merge, result, published, MERGE_CLOCK + 1).await.unwrap();
        }
        // No merge_attempt_ended: emulate a death after upload or log append.
        drop(ingestor);
        assert_backlog_readable(&lab).await;
        let mut ingestor = lab.open(MERGE_CLOCK + 2).await;
        let plan = plan_merges_with(&ingestor.live_parts(), MERGE_CLOCK + 2, &ingestor.cfg.merge_policy, true);
        let chunks = ingestor.converge_memory_bound_merges(plan);
        assert!(chunks.iter().flat_map(|m| &m.inputs).all(|part| part.level != Level::Hour));
        assert_eq!(hour_parts(&ingestor).iter().any(|part| part.part_id == output_id), after_append);
        let mut now = MERGE_CLOCK + 3;
        for _ in 0..OBJECTS {
            ingestor.tick(now).await.unwrap();
            settle_merges(&ingestor).await;
            ingestor.tick(now + 1).await.unwrap();
            now += 60_001;
        }
        settle_merges(&ingestor).await;
        ingestor.tick(now).await.unwrap();
        assert_backlog_readable(&lab).await;
        if after_append {
            assert!(hour_parts(&ingestor).iter().any(|part| part.part_id == output_id), "committed chunk remains final");
        }
        let settled = hour_parts(&ingestor);
        assert_eq!(settled.iter().filter(|part| part.level != Level::Hour).count(), usize::from(after_append), "odd leftover stays readable");
        drop(ingestor);
        let mut reopened = lab.open(now + 1).await;
        reopened.tick(now + 2).await.unwrap();
        assert!(!reopened.merge_in_flight.iter().any(|flight| i64::from(flight.merge.event_hour) == HOUR));
        assert_eq!(hour_parts(&reopened), settled);
        lab.land("replayed-uids", &[event(0), event(ROWS_PER_OBJECT), event(OBJECTS * ROWS_PER_OBJECT - 1)], now + 2);
        reopened.tick(now + 3).await.unwrap();
        reopened.flush_now(now + 4).await.unwrap();
        assert!(reopened.health().duplicates_dropped_total >= 3, "restart retains dedup coverage of chunks and leftover parts");
        assert_backlog_readable(&lab).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreadable_attempt_ledger_defers_compaction_while_ingestion_commits() {
    let lab = Lab::new();
    lab.land_backlog().await;
    let path = lab.root.join("work/merge-attempts.json");
    let broken = b"{unreadable";
    std::fs::write(&path, broken).unwrap();
    let mut ingestor = lab.open(MERGE_CLOCK).await;
    lab.land("fresh", &[event(2_000_000)], MERGE_CLOCK - 1);
    ingestor.tick(MERGE_CLOCK).await.unwrap();
    ingestor.flush_now(MERGE_CLOCK + 1).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 1);
    assert!(ingestor.merge_in_flight.is_empty());
    assert_eq!(std::fs::read(path).unwrap(), broken, "never overwrite unknown permanent policy");
}

#[tokio::test(flavor = "current_thread")]
async fn a_left_unmerged_hour_retries_only_on_limit_growth_and_leaves_no_stale_gauge_after_retirement() {
    let lab = Lab::new();
    lab.land_backlog().await;
    let id = merge_id(Level::Hour.code(), HOUR as i32);
    fn tiny() -> Option<(u64, u64)> { Some((0, 64 << 10)) }
    fn grown() -> Option<(u64, u64)> { Some((0, 128 << 10)) }
    super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(tiny));
    let mut ledger = MergeAttempts::open(&lab.root.join("work"), MERGE_CLOCK);
    while !ledger.left_unmerged(&id) {
        let inputs = ledger.max_inputs(&id).unwrap_or(OBJECTS);
        ledger.shrink(&id, MERGE_CLOCK, inputs).unwrap();
    }
    let failures = ledger.entry(&id).unwrap().failures;
    let mut ingestor = lab.open(MERGE_CLOCK).await;
    ingestor.tick(MERGE_CLOCK).await.unwrap();
    assert!(ingestor.merge_in_flight.is_empty());
    assert_eq!(ingestor.health().merge_backlog, 0);
    assert_eq!(ingestor.health().merges_left_unmerged, 1);
    assert!(ingestor.merge_attempts.begin(&id, 1).is_err(), "even a rewrite cannot bypass the stop");

    super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(grown));
    let mut now = MERGE_CLOCK + 1;
    for attempt in 1..=2 {
        ingestor.tick(now).await.unwrap();
        assert!(ingestor.merge_in_flight.iter().any(|flight| i64::from(flight.merge.event_hour) == HOUR));
        settle_merges(&ingestor).await;
        ingestor.tick(now + 1).await.unwrap();
        assert_eq!(ingestor.merge_attempts.entry(&id).unwrap().failures, failures + attempt);
        now += super::super::merge_attempts::PARK_MAX_MS;
    }
    assert_eq!(ingestor.merge_attempts.entry(&id).unwrap().left_unmerged_at_limit, Some(128 << 10));
    ingestor.tick(now).await.unwrap();
    assert!(ingestor.merge_in_flight.is_empty(), "same grown limit never re-arms twice");
    assert_eq!(ingestor.health().merge_backlog, 0);
    assert_eq!(ingestor.health().merges_left_unmerged, 1);
    assert_backlog_readable(&lab).await;

    let parts = hour_parts(&ingestor).into_iter().map(|part| part.part_id).collect();
    ingestor.log.append(LogOp::Retire { parts, reason: crate::parts::part_log::RetireReason::Retention,
        deletion_unit: uuid::Uuid::new_v4().to_string() }, now + 1).await.unwrap();
    ingestor.tick(now + 2).await.unwrap();
    assert_eq!(ingestor.health().merges_left_unmerged, 0);
    assert!(ingestor.merge_attempts.entry(&id).is_none(), "retired data leaves no permanent policy behind");
    super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
}
