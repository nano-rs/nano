// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4796 on a real ingestor. A multi-hour L0 backlog under a small
//! memory limit, with ingest's own memory high, converges to merged `h`
//! parts. It never enters the quarantine loop, and the backlog strictly
//! decreases.
//!
//! A hosted tenant in the reference cell, 2026-10-28.
//! The ingest role's `memory.max` is 3.41 GB. Its assignment memory cap, a
//! sizing figure at 40 % of the eps curve, is 1.37 GB, and ingest's steady
//! unreclaimable memory is ~1.18 GB. The NAN-4755 guard measured
//! against min(memory.max, cap), so it stopped every merge at ~1.18 GB, the
//! 164-input hour and the smallest-shape 6-input chunk alike. On top of the
//! ledger's shrink, each stop was quarantined with a doubling backoff
//! (1 -> 32 min). In 47 min no `h` merge committed, and L0 grew from
//! 162 to 253 parts.
//!
//! Here the production scheduler runs (background lanes, static part
//! store and signer) on a realistic clock (61 s a tick, never jumping past
//! a backoff). The guard reads a fixed baseline, the ingest heap
//! above it, and the limit that production picks
//! ([`super::super::merge_lanes::guard_limit`]): the role's `memory.max`
//! beside a sizing cap that the baseline alone already exceeds.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::merge_attempts::{merge_id, MAX_SHIFT};
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use serde_json::json;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};

const TENANT: &str = "47960000-0000-4000-8000-000000000001";
/// The backlog's first event hour; it spans [`HOURS`] hours.
const FIRST_HOUR: i64 = 492_200;
const HOURS: i64 = 3;
/// L0 parts each backlog hour holds (FP: 50-164).
const OBJECTS_PER_HOUR: usize = 12;
const ROWS_PER_OBJECT: usize = 1_000;
/// Ingest lands the backlog after its last hour ...
const INGEST_CLOCK: i64 = (FIRST_HOUR + HOURS) * 3_600_000 + 600_000;
/// ... and merges once every backlog hour is sealed.
const MERGE_CLOCK: i64 = (FIRST_HOUR + HOURS + 2) * 3_600_000;
/// The production scheduler's cadence: about one merge round a minute.
const TICK_MS: i64 = 61_000;

fn event(hour: i64, i: usize) -> Value {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(hour * 3_600 + (i as i64 * 7) % 3_500, 0).unwrap();
    let uid = format!("nan4796-{hour}-{i:07}");
    let raw = format!("<raw id='{i}'>{}</raw>", "r".repeat(600 + i % 17));
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 23)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("Authentication {i} {}", "m".repeat(400 + i % 13)), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "backlog", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.{}.{}.{}", i % 3, i % 200, i % 250), "hostname": format!("ws-{}.corp.local", i % 41)},
        "dst_endpoint": {"ip": format!("192.168.{}.{}", i % 5, i % 20)},
        "user": {"name": format!("user{}", i % 23), "uid": format!("S-1-5-21-{}", i % 23)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": 300_201
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

/// The role's `memory.max` the guard sees (0: no limit, unmeasured), the
/// ingest memory held before the merge phase (the FP steady state) and
/// the heap counted from there.
static CGROUP_MAX: AtomicU64 = AtomicU64::new(0);
/// The assignment's sizing cap beside it (a test-local stand-in for the
/// process-wide `merge::memory_cap_bytes`, which parallel tests share).
static SIZING_CAP: AtomicU64 = AtomicU64::new(0);
static BASELINE: AtomicU64 = AtomicU64::new(0);
static BASE: AtomicIsize = AtomicIsize::new(0);

/// What production's guard reads: baseline plus heap in use, against
/// the limit [`super::super::merge_lanes::guard_limit`] picks from the
/// cgroup's `memory.max` and the assignment's sizing cap.
fn probe() -> Option<(u64, u64)> {
    let cgroup = CGROUP_MAX.load(Ordering::SeqCst);
    if cgroup == 0 {
        return None;
    }
    let used = BASELINE.load(Ordering::SeqCst) + (crate::test_heap::live() - BASE.load(Ordering::SeqCst)).max(0) as u64;
    let limit = super::super::merge_lanes::guard_limit(Some(cgroup), Some(SIZING_CAP.load(Ordering::SeqCst)))?;
    Some((used, limit))
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
            signer: Box::leak(Box::new(LocalPartSigner::new("lab-signer-nan4796", ed25519_dalek::SigningKey::from_bytes(&[96; 32])).unwrap())),
            _root: dir,
            root,
        }
    }

    fn config(&self) -> IngestConfig {
        let mut config = IngestConfig::new(TENANT, self.root.join("work"));
        config.prevalence_enabled = false;
        config.background_merges = true;
        // Every object stays its own L0 part until the hour's `h` merge.
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
        self.spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: at }).unwrap();
    }

    /// The backlog: [`OBJECTS_PER_HOUR`] L0 parts in each of [`HOURS`] hours.
    async fn land_backlog(&self) {
        let mut ingestor = self.open(INGEST_CLOCK).await;
        let mut n = 0;
        for hour in FIRST_HOUR..FIRST_HOUR + HOURS {
            for object in 0..OBJECTS_PER_HOUR {
                let at = INGEST_CLOCK + n * 1_000;
                n += 1;
                let first = object * ROWS_PER_OBJECT;
                self.land(&format!("backlog-{hour}-{object:03}"),
                    &(first..first + ROWS_PER_OBJECT).map(|i| event(hour, i)).collect::<Vec<_>>(), at - 500);
                let report = ingestor.tick(at).await.unwrap();
                assert_eq!(report.admitted_rows, ROWS_PER_OBJECT as u64, "{hour}/{object}: {report:?}");
                ingestor.flush_now(at + 1).await.unwrap();
            }
        }
        assert_eq!(backlog(&ingestor), HOURS as usize * OBJECTS_PER_HOUR, "one L0 part per object");
    }
}

fn in_backlog(part: &PartRef) -> bool {
    (FIRST_HOUR..FIRST_HOUR + HOURS).contains(&i64::from(part.event_hour))
}

/// The backlog: unmerged (non-`h`) parts of the backlog hours.
fn backlog(ingestor: &Ingestor<'_>) -> usize {
    ingestor.live_parts().iter().filter(|part| in_backlog(part) && part.level != Level::Hour).count()
}

async fn settle_merges(ingestor: &Ingestor<'_>) {
    while ingestor.merge_in_flight.iter().any(|flight| !flight.handle.is_finished()) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

struct Drained {
    /// Backlog after every tick, starting with the landed one.
    trace: Vec<usize>,
    /// Heap high-water mark above the phase's start.
    peak: isize,
    stops: u64,
    failures: u64,
    fresh: u64,
    rows_committed: u64,
    parts: Vec<PartRef>,
    shrunk: bool,
}

/// Run the production scheduler at [`TICK_MS`] a tick, with fresh data
/// landing every tick, until no backlog-hour merge is planned or running.
/// `cgroup_max` 0 measures without a limit.
fn drain(lab: &Lab, cgroup_max: u64, baseline: u64, sizing_cap: u64, max_ticks: usize) -> Drained {
    let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    SIZING_CAP.store(sizing_cap, Ordering::SeqCst);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
        .on_thread_start(|| crate::test_heap::track_current_thread(true)).build().unwrap();
    crate::test_heap::track_current_thread(true);
    let drained = runtime.block_on(async {
        let mut ingestor = lab.open(MERGE_CLOCK).await;
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(probe));
        BASE.store(crate::test_heap::reset_peak(), Ordering::SeqCst);
        BASELINE.store(baseline, Ordering::SeqCst);
        CGROUP_MAX.store(cgroup_max, Ordering::SeqCst);
        let (mut now, mut fresh, mut trace, mut shrunk) = (MERGE_CLOCK, 0_u64, vec![backlog(&ingestor)], false);
        loop {
            assert!(trace.len() <= max_ticks, "the backlog did not converge in {max_ticks} ticks: {trace:?}");
            let tick = trace.len();
            let first = 5_000_000 + tick * 50;
            lab.land(&format!("fresh-{tick:03}"), &(first..first + 50).map(|i| {
                let mut row = event(FIRST_HOUR, i);
                row["time"] = json!(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now - 1_000).unwrap().to_rfc3339());
                row
            }).collect::<Vec<_>>(), now - 1_000);
            ingestor.tick(now).await.unwrap();
            ingestor.flush_now(now + 1).await.unwrap();
            fresh += 50;
            // An empty buffer: the history lanes may start hour merges.
            ingestor.tick(now + 2).await.unwrap();
            settle_merges(&ingestor).await;
            // Reap: commit, or record a guard stop.
            ingestor.tick(now + 3).await.unwrap();
            shrunk |= (FIRST_HOUR..FIRST_HOUR + HOURS).any(|hour| ingestor.merge_attempts
                .entry(&merge_id(Level::Hour.code(), hour as i32)).is_some_and(|entry| entry.shift > 0 || entry.max_inputs.is_some()));
            trace.push(backlog(&ingestor));
            let planned = plan_merges_with(&ingestor.live_parts(), now + 3, &ingestor.cfg.merge_policy, true);
            let pending = ingestor.converge_memory_bound_merges(planned).iter().filter(|merge| merge.inputs.iter().all(in_backlog)).count();
            if pending == 0 && !ingestor.merge_in_flight.iter().any(|flight| flight.merge.inputs.iter().all(in_backlog)) {
                break;
            }
            now += TICK_MS;
        }
        CGROUP_MAX.store(0, Ordering::SeqCst);
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
        let health = ingestor.health();
        Drained {
            trace,
            peak: crate::test_heap::peak() - BASE.load(Ordering::SeqCst),
            stops: health.merge_memory_stops_total,
            failures: health.merge_failures_total,
            fresh,
            rows_committed: health.rows_committed_total,
            parts: ingestor.live_parts().into_iter().filter(in_backlog).collect(),
            shrunk,
        }
    });
    crate::test_heap::track_current_thread(false);
    drained
}

fn land(lab: &Lab) {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(lab.land_backlog());
}

/// The longest run of ticks without the backlog shrinking: the attempts
/// one hour may need to fit (every shape step, then halving the fan-in
/// down to two), plus one tick to start.
fn stall_bound() -> usize {
    MAX_SHIFT as usize + (OBJECTS_PER_HOUR as f64).log2().ceil() as usize + 2
}

/// Convergence proof: the backlog never grows, it strictly decreases
/// within every [`stall_bound`] window of ticks, and it ends with at most
/// one lone part per hour (a merge needs two inputs).
fn assert_converges(trace: &[usize]) {
    for (tick, pair) in trace.windows(2).enumerate() {
        assert!(pair[1] <= pair[0], "backlog grew at tick {}: {trace:?}", tick + 1);
    }
    let mut last_drop = 0;
    for tick in 1..trace.len() {
        if trace[tick] < trace[tick - 1] {
            last_drop = tick;
        }
        let done = trace[tick] <= HOURS as usize;
        assert!(done || tick - last_drop <= stall_bound(), "no progress for {} ticks (bound {}): {trace:?}", tick - last_drop, stall_bound());
    }
    assert!(*trace.last().unwrap() <= HOURS as usize, "at most one lone part per hour: {trace:?}");
    assert!(trace.last() < trace.first(), "the backlog shrank: {trace:?}");
}

/// The incident, end to end. The ingest baseline alone is above 85 % of
/// the sizing cap (where the pre-NAN-4796 guard stopped every merge). The
/// role's `memory.max` leaves the merges 60 % of the full-shape hour
/// merge's peak above that baseline, so the hours must shrink and split to
/// fit. Every hour converges into `h` parts with every row, on a realistic
/// clock, with zero quarantined failures. Fresh data commits throughout,
/// and memory never reaches `memory.max`.
#[test]
fn a_multi_hour_backlog_under_a_small_limit_and_high_baseline_converges_without_quarantine() {
    let free = { let lab = Lab::new(); land(&lab); drain(&lab, 0, 0, 0, 40) };
    assert_eq!((free.stops, free.failures), (0, 0), "no limit, no stop");
    assert_converges(&free.trace);
    let full_peak = free.peak.max(1) as u64;

    let room = full_peak / 10 * 6;
    let baseline = 2 * room;
    // FP: steady ingest at 86 % of the sizing cap; here above 100 %.
    let sizing_cap = baseline / 20 * 19;
    let cgroup_max = ((baseline + room) as f64 / super::super::merge_quota::MEMORY_GUARD_SHARE) as u64;
    assert!(baseline as f64 >= sizing_cap as f64 * super::super::merge_quota::MEMORY_GUARD_SHARE,
        "fixture: under min(memory.max, cap) the baseline alone trips the guard");
    assert!((baseline as f64) < cgroup_max as f64 * super::super::merge_quota::MERGE_START_SHARE,
        "fixture: the role has room to start a merge");

    let lab = Lab::new();
    land(&lab);
    let backlog_rows = (HOURS as usize * OBJECTS_PER_HOUR * ROWS_PER_OBJECT) as u64;
    // Every hour, every rung, with slack: never unbounded.
    let run = drain(&lab, cgroup_max, baseline, sizing_cap, HOURS as usize * (stall_bound() + 2) + 8);
    eprintln!("NAN-4796: full-shape peak {} KiB; baseline {} KiB, memory.max {} KiB, sizing cap {} KiB: {} ticks, {} guard stops, \
        peak {} KiB, backlog {:?}", full_peak >> 10, baseline >> 10, cgroup_max >> 10, sizing_cap >> 10, run.trace.len() - 1,
        run.stops, run.peak >> 10, run.trace);
    assert!(run.shrunk && run.stops >= 1, "the fixture must make the full shape not fit");
    assert_eq!(run.failures, 0, "no merge was quarantined: guard stops are the ledger's, not a failing input's");
    assert_converges(&run.trace);
    assert!(baseline + (run.peak.max(0) as u64) < cgroup_max, "never reached memory.max (no OOM)");
    assert_eq!(run.parts.iter().map(|part| part.rows).sum::<u64>(), backlog_rows,
        "every backlog row stays live (fresh rows land in a later hour)");
    for hour in FIRST_HOUR..FIRST_HOUR + HOURS {
        let parts = run.parts.iter().filter(|part| i64::from(part.event_hour) == hour).collect::<Vec<_>>();
        assert!(parts.iter().any(|part| part.level == Level::Hour), "hour {hour} merged into `h`: {parts:?}");
        assert!(parts.iter().filter(|part| part.level != Level::Hour).count() <= 1, "hour {hour}: at most a lone leftover");
    }
    assert_eq!(run.rows_committed, run.fresh, "ingest committed every fresh row beside the merges");
}

/// The same backlog where the guard stops come from memory held
/// elsewhere: a merge that started without the normal room is not shrunk
/// or split and is not quarantined. It waits briefly at its shape, a
/// bounded number of times. A stop the merge caused shrinks it, also
/// without quarantine. Once the memory frees up, every hour merges.
#[test]
fn stops_from_memory_held_elsewhere_wait_at_full_shape_without_quarantine() {
    let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    land(&lab);
    // Admission holds the process past the start share, at the guard.
    fn near_guard() -> Option<(u64, u64)> { Some((860 << 20, 1_000 << 20)) }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let mut ingestor = lab.open(MERGE_CLOCK).await;
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(Some(near_guard));
        let mut now = MERGE_CLOCK;
        for _ in 0..3 {
            ingestor.tick(now).await.unwrap();
            assert!(ingestor.merge_in_flight.is_empty(), "past the start share: no hour merge starts");
            now += TICK_MS;
        }
        // A merge that started at 80 % (past the 70 % start share) and was
        // stopped: memory held elsewhere left it no room.
        let id = merge_id(Level::Hour.code(), FIRST_HOUR as i32);
        let key = (Level::Hour.code().to_string(), FIRST_HOUR as i32);
        let stop = anyhow::Error::from(super::super::merge_quota::MemoryPressure { used_bytes: 860, limit_bytes: 1_000, start_used_bytes: 800 });
        assert!(!super::super::merge_quota::memory_pressure_of(&stop).unwrap().charged_to_merge());
        ingestor.merge_attempts.begin(&id, OBJECTS_PER_HOUR).unwrap();
        ingestor.merge_attempt_ended(&key, OBJECTS_PER_HOUR, Some(&stop), now);
        ingestor.quarantine_merge(key.clone(), now, &stop);
        assert_eq!(ingestor.merge_attempts.shift(&id), 0, "not shrunk");
        assert_eq!(ingestor.merge_attempts.max_inputs(&id), None, "not split");
        assert_eq!(ingestor.health().merge_failures_total, 0, "not a failure");
        assert_eq!(ingestor.merge_quarantine.get(&key), Some(&(0, now + MEMORY_STOP_RETRY_MS)), "a short uncounted wait");
        // Bounded: past MAX_UNCHARGED_MEMORY_STOPS such stops count again.
        for _ in 1..MAX_UNCHARGED_MEMORY_STOPS {
            ingestor.merge_attempts.begin(&id, OBJECTS_PER_HOUR).unwrap();
            ingestor.merge_attempt_ended(&key, OBJECTS_PER_HOUR, Some(&stop), now);
        }
        assert_eq!(ingestor.merge_attempts.shift(&id), 0, "still waiting at its shape");
        ingestor.merge_attempts.begin(&id, OBJECTS_PER_HOUR).unwrap();
        ingestor.merge_attempt_ended(&key, OBJECTS_PER_HOUR, Some(&stop), now);
        assert_eq!(ingestor.merge_attempts.shift(&id), 1, "the wait is bounded: the ladder resumes");
        ingestor.merge_memory_waits.clear();
        // A stop the merge caused shrinks it and still is not quarantined.
        let own = anyhow::Error::from(super::super::merge_quota::MemoryPressure { used_bytes: 860, limit_bytes: 1_000, start_used_bytes: 100 });
        ingestor.merge_quarantine.remove(&key);
        ingestor.merge_attempts.begin(&id, OBJECTS_PER_HOUR).unwrap();
        ingestor.merge_attempt_ended(&key, OBJECTS_PER_HOUR, Some(&own), now);
        ingestor.quarantine_merge(key.clone(), now, &own);
        assert_eq!(ingestor.merge_attempts.shift(&id), 2, "its own growth: one shape step smaller");
        assert_eq!(ingestor.merge_quarantine.get(&key), Some(&(0, now + 1)), "no backoff: only not again on this tick");
        assert_eq!(ingestor.health().merge_failures_total, 0);
        // Memory freed: every hour merges.
        super::super::merge_quota::MEMORY_PROBE_FOR_TEST.set(None);
        for _ in 0..HOURS * 2 {
            ingestor.tick(now).await.unwrap();
            settle_merges(&ingestor).await;
            ingestor.tick(now + 1).await.unwrap();
            now += TICK_MS;
        }
        assert_eq!(backlog(&ingestor), 0, "every backlog hour merged");
    });
}
