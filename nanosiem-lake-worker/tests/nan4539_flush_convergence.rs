// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4539 Step 2: backlog x IO-cost convergence of bounded flush overlap,
//! through the production `Ingestor::open` constructor, its scheduler
//! (`tick` with the cell's wake/1 s loop), real bronze admission, real
//! Parquet/token/partial part builds, real signatures, the real part log and
//! an order-checking source queue. Only the IO boundary and the clock are
//! fakes.
//!
//! # The model (read before quoting any number)
//!
//! - **Clock**: Tokio's paused clock. Virtual time advances only while every
//!   task waits on a timer, so admission/build CPU costs ZERO modeled time;
//!   the modeled time is IO delay plus the cell loop's 1 s idle sleep.
//! - **IO delays are MODELED, not measured.** No per-request production
//!   capture exists. `ESTIMATE` is calibrated from the T84 large-tenant read-only RCA
//!   (the large-tenant catch-up throughput RCA, 596 EPS, ~9.9k rows per commit jump,
//!   ~16.7 s per serial flush) sampled stage residency per flush: build
//!   16.3% = 2.72 s, publication 43.5% = 7.3 s over its two sequential write
//!   rounds (part files, then provenance) = 3.65 s per object write,
//!   part-log append 14.8% = 2.47 s, prevalence apply 20.9% = 3.49 s. (The
//!   RCA's Little's-law native occupancy, authorize ~1.95 s + PUT ~1.24 s +
//!   complete ~2.00 s, would be 5.19 s per write; the residency figure is
//!   used because it reproduces the observed serial cadence.) These are
//!   occupancy/residency estimates, not latency histograms. `THREE_X` multiplies every delay by three as a **p95
//!   stand-in**; it is not a measured percentile. `ZERO` removes IO cost.
//! - Build CPU (zero modeled time) is charged as extra delay on each L0
//!   *data* object PUT (the first wave after the build in the same flight,
//!   written in parallel, so it lands once per flight). Prevalence is
//!   disabled here (its local SlateDB would race the paused clock); its
//!   apply estimate is charged on the `add` entry's append, which is where
//!   the production commit awaits it.
//! - Every PUT takes one permit of a FIFO 32-permit pool, as the production
//!   native writer's shared envelope does (`NativePartWriter::write_guard`,
//!   proven by its own unit test); merges share it.
//! - **Owner-call pacing is modeled** exactly as the native writer paces it:
//!   one process-wide 50 ms slot (300 EPS: the 3072 requests/min floor)
//!   shared by both publications, merges and appends, two calls per write
//!   (authorize before the PUT, complete after it), on top of the modeled
//!   IO delay. Every cost case pays it, `ZERO` included.
//! - **Not modeled** (what this suite does not prove): prevalence under
//!   overlap (disabled), build/admission CPU contention (CPU is free), the
//!   real `EdgeLogSource` (a spool queue stands in; see the edge tests), the
//!   cell constructor and loop (see `cell.rs` tests), and physical or live
//!   EPS.
//! - **Scaling**: rows are real (40 per object, 300 EPS offered = 7.5 objects
//!   per modeled second). With the serial path's fixed 256-notice pending
//!   window that cuts ~10k-row serial flushes, T84's observed commit jump
//!   (~9.9k rows); the serial baseline is a calibration check against T84's
//!   596 EPS, reported on every run. Backlog durations are
//!   scaled down per case: the throughput gates use `ONE_HOUR_SCALE` (4)
//!   and `THREE_HOUR_SCALE` (12), 270,000 backlog rows each (the zero-cost
//!   3h case 324,000 at scale 10, since its flushes are cut larger), so at
//!   least ten flushes commit in steady state; the short-backlog smoke, the tight
//!   budget and the failure cases use `SMOKE_SCALE` (60). Catch-up time
//!   scales the same way at a steady service rate, B/(mu - lambda): the
//!   deadline is 5,400 s or 1,800 s divided by the case's scale. The gated
//!   service rate is committed rows per modeled second over the steady-state
//!   window (first backlog commit to the commit at catch-up); the whole-run
//!   rate, offered rate and net drain are reported separately.
//! - **Pacing gaps**: the owner sign RPCs (`HttpPartSigner`) are not
//!   charged, owner 503/504 retry windows and journal replay are not
//!   modeled, and non-native checkpoint keys are paced here but not in
//!   production (a slight overcharge).
//!
//! These runs bound scheduling, ordering and request cost. They are not a
//! physical or live EPS claim; the README's offline benchmark section says
//! how the next train recalibrates from the Step 1 histograms.

use anyhow::Result;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::dedup::read_time_uids;
use nanosiem_lake_worker::part_ingest::discovery::NoticeHandle;
use nanosiem_lake_worker::part_ingest::ingest::{buffer_budget_for, seed_schema};
use nanosiem_lake_worker::part_ingest::merge::set_memory_budget;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::format::{LogKeys, PartKeys};
use nanosiem_lake_worker::parts::levels::DEFAULT_FLUSH_MAX_AGE_MS;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, LogEntry, LogOp, ObjectStore, SourceRef};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use nanosiem_lake_worker::parts::sha256_hex;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d4539";
/// 2026-09-25T00:00:00Z
const DAY0_S: i64 = 1_790_294_400;
const OFFERED_EPS: f64 = 300.0;
/// Source object shapes. `SMALL` is the Step 2 suite's fixture; `SEGMENT`
/// is a large-tenant edge segment, read-only from its cell 2026-10-26
/// 00:34-00:47Z: 2,908-5,735 rows per flush over 4-8 segments, about 728
/// rows a segment, and about 5.6 KB of Arrow per buffered row (22.8 MB for
/// 4,052 rows); `pad_bytes` of `raw_data` filler brings the fixture row there.
#[derive(Clone, Copy, Debug)]
struct Shape {
    name: &'static str,
    rows_per_object: usize,
    pad_bytes: usize,
}
const SMALL: Shape = Shape { name: "small", rows_per_object: 40, pad_bytes: 0 };
const SEGMENT: Shape = Shape { name: "segment", rows_per_object: 728, pad_bytes: 4_096 };
/// The large tenant's ingest memory cap (its status `budget.ingest_memory_cap_bytes`).
const B12_INGEST_MEMORY_CAP: u64 = 5_631_901_696;
/// Modeled milliseconds between two arriving objects (133.3 ms).
const fn arrival_ms(index: usize, shape: Shape) -> u64 {
    (index as u64 * shape.rows_per_object as u64 * 1_000) / 300
}
/// The short-backlog smoke scale (see [`one_hour_backlog_smoke_meets_its_deadline_and_beats_serial`]).
const SMOKE_SCALE: f64 = 60.0;
/// The throughput gates need steady state: at least this many backlog
/// flushes between the first backlog commit and catch-up.
const MIN_STEADY_FLUSHES: usize = 10;
/// Required total service while backlogged (3x offered).
const REQUIRED_SERVICE_EPS: f64 = 900.0;
/// Caught up: every backlog notice is acknowledged (the frontier passed the
/// outage) AND the oldest unacknowledged notice is at most this old (twice
/// the catch-up flush age cap). Real seconds, NOT scaled: arrivals run at the
/// real 300 EPS, only the backlog length is scaled. Once the frontier passed,
/// the oldest pending notice is a fresh arrival, so in practice "caught up"
/// is "every backlog notice acked"; the lag bound only matters for a tail
/// that falls far behind again.
const CAUGHT_UP_LAG_MS: u64 = 60_000;
/// The production native writer's shared write envelope.
const ENVELOPE: usize = 32;

#[derive(Clone, Copy, Debug)]
struct Cost {
    name: &'static str,
    /// Native authorize + PUT + complete occupancy per object write.
    object_put_ms: u64,
    /// Build residency, charged once per flight on its L0 data objects.
    build_ms: u64,
    /// Part-log append residency, plus the prevalence apply on an `add`.
    log_put_ms: u64,
    prevalence_ms: u64,
    /// No Step 1 timing exists for reads; an explicit assumption.
    read_ms: u64,
    /// Per-row parts (Step 3; 0 in the Step 2 costs): build per row of each
    /// L0 data object, prevalence apply per row of each `add`.
    build_us_per_row: u64,
    prevalence_us_per_row: u64,
}

const ZERO: Cost = Cost { name: "zero", object_put_ms: 0, build_ms: 0, log_put_ms: 0, prevalence_ms: 0, read_ms: 0, build_us_per_row: 0, prevalence_us_per_row: 0 };
const ESTIMATE: Cost = Cost { name: "estimate(MODELED)", object_put_ms: 3_650, build_ms: 2_720, log_put_ms: 2_470, prevalence_ms: 3_490, read_ms: 100, build_us_per_row: 0, prevalence_us_per_row: 0 };
const THREE_X: Cost = Cost {
    name: "3x-estimate(MODELED p95 stand-in)",
    object_put_ms: 3 * ESTIMATE.object_put_ms,
    build_ms: 3 * ESTIMATE.build_ms,
    log_put_ms: 3 * ESTIMATE.log_put_ms,
    prevalence_ms: 3 * ESTIMATE.prevalence_ms,
    read_ms: 3 * ESTIMATE.read_ms,
    build_us_per_row: 0,
    prevalence_us_per_row: 0,
};

/// Step 3 costs: the same T84 per-flush residency, split into fixed and
/// per-row parts at T84's mean flush (10,045 rows over its 18 sampled
/// flushes). Build is all per row (CPU over the rows). Object writes and the
/// part-log append stay fixed per request. Prevalence apply: T84's sampled
/// stage maxima show no detectable row dependence over 5,982-13,583 rows
/// (least squares 39 us/row, r = 0.11, 12 flushes with a sample in the
/// stage), so the fitted split charges 27% of its 3.49 s per row and 73%
/// per `add`. `*_LINEAR_PREVALENCE` charges all of it per row: the worst
/// case, reported, not gated. MODELED, from sampled residency.
const ROW_ESTIMATE: Cost = Cost {
    name: "row-estimate(MODELED, fitted prevalence)",
    object_put_ms: 3_650, build_ms: 0, log_put_ms: 2_470, prevalence_ms: 2_548, read_ms: 100,
    build_us_per_row: 271, prevalence_us_per_row: 94,
};
const ROW_THREE_X: Cost = Cost {
    name: "row-3x(MODELED p95 stand-in, fitted prevalence)",
    object_put_ms: 3 * 3_650, build_ms: 0, log_put_ms: 3 * 2_470, prevalence_ms: 3 * 2_548, read_ms: 300,
    build_us_per_row: 3 * 271, prevalence_us_per_row: 3 * 94,
};
const ROW_THREE_X_LINEAR_PREVALENCE: Cost = Cost {
    name: "row-3x(MODELED p95 stand-in, linear prevalence)",
    object_put_ms: 3 * 3_650, build_ms: 0, log_put_ms: 3 * 2_470, prevalence_ms: 0, read_ms: 300,
    build_us_per_row: 3 * 271, prevalence_us_per_row: 3 * 347,
};

/// Rows of a Parquet object (its footer), for per-row build cost.
fn parquet_rows(bytes: &[u8]) -> u64 {
    use parquet::file::reader::FileReader;
    parquet::file::reader::SerializedFileReader::new(bytes::Bytes::copy_from_slice(bytes))
        .map_or(0, |reader| reader.metadata().file_metadata().num_rows().max(0) as u64)
}

/// Rows of an `add` entry, for per-row prevalence cost.
fn add_rows(bytes: &[u8]) -> Option<u64> {
    match LogEntry::parse_bytes(bytes, TENANT).ok()?.op {
        LogOp::Add { parts, .. } => Some(parts.iter().map(|part| part.rows).sum()),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    /// The pre-NAN-4539 production path: one flight, ready commits wait
    /// for the next ingest phase, one source range.
    Serial,
    /// The production constructor defaults (bounded overlap).
    Bounded,
}

/// Counted IO with modeled delays (see the module docs).
struct ModeledStore {
    inner: LocalObjectStore,
    cost: Cost,
    envelope: tokio::sync::Semaphore,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    l0_puts: AtomicUsize,
    other_part_puts: AtomicUsize,
    log_puts: AtomicUsize,
    put_bytes: AtomicU64,
    put_conflicts: AtomicUsize,
    gets: AtomicUsize,
    lists: AtomicUsize,
    deletes: AtomicUsize,
    /// Fail the L0 data PUT with these ordinals once (transient owner 503).
    fail_l0_data: BTreeSet<usize>,
    l0_data_puts: AtomicUsize,
    failures: AtomicUsize,
    /// The production native writer's owner-call pacer
    /// (`NativePartWriter::pace_owner_call`): one process-wide slot every
    /// [`OWNER_CALL_INTERVAL`], shared by every publication, merge and
    /// part-log append; each native write pays two calls (authorize before
    /// the PUT, complete after it).
    next_owner_call: tokio::sync::Mutex<tokio::time::Instant>,
    pacer_wait_us: AtomicU64,
    owner_calls: AtomicUsize,
}

/// `NativePartWriter::with_ingest_eps` at 300 EPS (the 3072 requests/min
/// floor): 120 s / 2400 = 50 ms between owner calls.
/// Guards the process-wide merge decode window (`merge::set_memory_budget`)
/// across the concurrently running cases of this binary.
static MERGE_WINDOW: std::sync::RwLock<()> = std::sync::RwLock::new(());

enum MergeWindow {
    Default(#[allow(dead_code)] std::sync::RwLockReadGuard<'static, ()>),
    Capped(#[allow(dead_code)] std::sync::RwLockWriteGuard<'static, ()>),
}

impl MergeWindow {
    fn hold(memory_cap: Option<u64>) -> Self {
        match memory_cap {
            None => Self::Default(MERGE_WINDOW.read().unwrap_or_else(|poisoned| poisoned.into_inner())),
            Some(cap) => {
                let guard = MERGE_WINDOW.write().unwrap_or_else(|poisoned| poisoned.into_inner());
                set_memory_budget(cap);
                Self::Capped(guard)
            }
        }
    }
}

impl Drop for MergeWindow {
    fn drop(&mut self) {
        if matches!(self, Self::Capped(_)) {
            set_memory_budget(0);
        }
    }
}

const OWNER_CALL_INTERVAL: Duration = Duration::from_millis(50);

impl ModeledStore {
    async fn pace_owner_call(&self) {
        let started = tokio::time::Instant::now();
        let mut next = self.next_owner_call.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + OWNER_CALL_INTERVAL;
        drop(next);
        self.owner_calls.fetch_add(1, Ordering::SeqCst);
        self.pacer_wait_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::SeqCst);
    }
    fn new(root: &Path, cost: Cost, fail_l0_data: BTreeSet<usize>) -> Self {
        Self {
            inner: LocalObjectStore::new(root).unwrap(), cost, envelope: tokio::sync::Semaphore::new(ENVELOPE),
            in_flight: AtomicUsize::new(0), peak_in_flight: AtomicUsize::new(0), l0_puts: AtomicUsize::new(0),
            other_part_puts: AtomicUsize::new(0), log_puts: AtomicUsize::new(0), put_bytes: AtomicU64::new(0),
            put_conflicts: AtomicUsize::new(0), gets: AtomicUsize::new(0), lists: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0), fail_l0_data, l0_data_puts: AtomicUsize::new(0), failures: AtomicUsize::new(0),
            next_owner_call: tokio::sync::Mutex::new(tokio::time::Instant::now()), pacer_wait_us: AtomicU64::new(0),
            owner_calls: AtomicUsize::new(0),
        }
    }
    fn total_requests(&self) -> usize {
        self.l0_puts.load(Ordering::SeqCst) + self.other_part_puts.load(Ordering::SeqCst) + self.log_puts.load(Ordering::SeqCst)
            + self.gets.load(Ordering::SeqCst) + self.lists.load(Ordering::SeqCst) + self.deletes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ObjectStore for ModeledStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(self.cost.read_ms)).await;
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let _permit = self.envelope.acquire().await.unwrap();
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(now, Ordering::SeqCst);
        let log = key.contains("/log/entries/");
        let l0 = key.contains("/parts/l0/");
        let data = l0 && key.contains("/data-");
        let mut delay = if log { self.cost.log_put_ms } else { self.cost.object_put_ms };
        if log && std::str::from_utf8(bytes).is_ok_and(|entry| entry.contains("\"add\"")) {
            delay += self.cost.prevalence_ms;
            if self.cost.prevalence_us_per_row > 0 {
                delay += add_rows(bytes).unwrap_or(0) * self.cost.prevalence_us_per_row / 1_000;
            }
        }
        let mut fail = false;
        if data {
            delay += self.cost.build_ms;
            if self.cost.build_us_per_row > 0 {
                delay += parquet_rows(bytes) * self.cost.build_us_per_row / 1_000;
            }
            let ordinal = self.l0_data_puts.fetch_add(1, Ordering::SeqCst);
            fail = self.fail_l0_data.contains(&ordinal);
        }
        if log {
            self.log_puts.fetch_add(1, Ordering::SeqCst);
        } else if l0 {
            self.l0_puts.fetch_add(1, Ordering::SeqCst);
        } else {
            self.other_part_puts.fetch_add(1, Ordering::SeqCst);
        }
        self.put_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.pace_owner_call().await; // authorize
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if !fail {
            self.pace_owner_call().await; // complete
        }
        let outcome = if fail {
            self.failures.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("modeled transient owner 503"))
        } else {
            self.inner.put_if_absent(key, bytes).await
        };
        if matches!(outcome, Ok(false)) {
            self.put_conflicts.fetch_add(1, Ordering::SeqCst);
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        outcome
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.other_part_puts.fetch_add(1, Ordering::SeqCst);
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(self.cost.read_ms)).await;
        self.inner.list(prefix).await
    }
}

/// The source queue with the edge contract checked at every call: at most
/// `ranges` ranges outstanding, acknowledged strictly in issue order, an ack
/// only after its `add` committed, no skip ack while a range is out.
struct ModelQueue<'a> {
    spool: SpoolQueue,
    parts: &'a LocalObjectStore,
    sources: &'a LocalObjectStore,
    ranges: usize,
    issued: Mutex<VecDeque<BTreeSet<String>>>,
    keys: Mutex<BTreeMap<String, String>>,
    /// Delivered, unacknowledged: key -> notified (modeled ms since start).
    unacked: Mutex<BTreeMap<String, i64>>,
    range_calls: AtomicUsize,
    ack_calls: AtomicUsize,
    acked: AtomicUsize,
    peak_outstanding: AtomicUsize,
}

#[async_trait]
impl NoticeQueue for ModelQueue<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let pending = self.spool.pending(max).await?;
        let mut keys = self.keys.lock().unwrap();
        for (handle, notice) in &pending {
            keys.insert(handle.0.clone(), notice.key.clone());
        }
        Ok(pending)
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        self.ack_calls.fetch_add(1, Ordering::SeqCst);
        let acked = handles.iter()
            .map(|h| self.keys.lock().unwrap().get(&h.0).cloned().expect("acked handle was pending"))
            .collect::<BTreeSet<_>>();
        if self.ranges > 1 || !self.issued.lock().unwrap().is_empty() {
            let issued = self.issued.lock().unwrap();
            let oldest = issued.front().ok_or_else(|| anyhow::anyhow!("an ack without an issued range"))?;
            anyhow::ensure!(*oldest == acked, "an ack out of issue order");
        }
        let live = load_log(self.parts, TENANT).await?;
        for key in &acked {
            let bytes = self.sources.get(key).await?.expect("source object");
            let source = SourceRef { key: key.clone(), version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "an ack before its add committed: {key}");
        }
        self.issued.lock().unwrap().pop_front();
        {
            let mut unacked = self.unacked.lock().unwrap();
            for key in &acked {
                unacked.remove(key);
            }
        }
        self.acked.fetch_add(handles.len(), Ordering::SeqCst);
        self.spool.ack(handles).await
    }
    async fn ack_skipped(&self, acks: &[(NoticeHandle, nanosiem_lake_worker::part_ingest::discovery::AckCounts)]) -> Result<()> {
        anyhow::ensure!(self.issued.lock().unwrap().is_empty(), "skips acked while a range is outstanding");
        let handles = acks.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>();
        {
            let mut unacked = self.unacked.lock().unwrap();
            for handle in &handles {
                if let Some(key) = self.keys.lock().unwrap().get(&handle.0) {
                    unacked.remove(key);
                }
            }
        }
        self.spool.ack(&handles).await
    }
    async fn range_for_flush(&self, sources: &[nanosiem_lake_worker::parts::provenance::SourceObject], _rejected: u64, _duplicate: u64)
        -> Result<Option<nanosiem_lake_worker::parts::EdgeLogRange>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        let mut issued = self.issued.lock().unwrap();
        let keys = sources.iter().map(|s| s.key.clone()).collect::<BTreeSet<_>>();
        // A spool range is `None`, so a retried flush asks again: the same
        // newest range, not a new one.
        if issued.back() == Some(&keys) {
            return Ok(None);
        }
        anyhow::ensure!(issued.len() < self.ranges, "a range issued beyond the queue's capacity");
        issued.push_back(keys);
        self.peak_outstanding.fetch_max(issued.len(), Ordering::SeqCst);
        Ok(None)
    }
    fn max_outstanding_ranges(&self) -> usize {
        self.ranges
    }
}

/// The NAN-2868 acceptance event shape (passes bronze admission).
fn event(uid: &str, time_ms: i64, i: usize, pad_bytes: usize) -> Value {
    let time = chrono::DateTime::from_timestamp_millis(time_ms).unwrap();
    let mut raw = format!("raw {uid} host-{} logon token{}", i % 7, i % 13);
    // Row-specific filler (not one repeated byte), so the row's Arrow size
    // is real; a cheap xorshift keeps it deterministic.
    let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while raw.len() < pad_bytes {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        raw.push_str(&format!(" {x:016x}"));
    }
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

/// The ordered source objects every run of a test shares (identical bytes,
/// order and event times for the serial and bounded runs).
struct Sources {
    _dir: tempfile::TempDir,
    store: LocalObjectStore,
    keys: Vec<String>,
}

/// Event time of object `index`: the arrival stream, oldest first, a few
/// minutes into an hour (a "3h" scaled backlog plus arrivals stays within a
/// couple of event hours, like a real ~30 s flush window).
const EVENT0_MS: i64 = (DAY0_S + 600) * 1_000;

fn sources(objects: usize, shape: Shape) -> Sources {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("bronze")).unwrap();
    let mut keys = Vec::with_capacity(objects);
    for o in 0..objects {
        let at = EVENT0_MS + arrival_ms(o, shape) as i64;
        let rows = shape.rows_per_object;
        let events = (0..rows)
            .map(|r| event(&format!("c-{o:06}-{r:02}"), at - 2_000 + (r as i64) * 2_000 / rows as i64, o * rows + r, shape.pad_bytes))
            .collect::<Vec<_>>();
        let key = format!("bronze/{o:06}.parquet");
        write_bronze(&dir.path().join(&key), &events);
        keys.push(key);
    }
    let store = LocalObjectStore::new(dir.path()).unwrap();
    Sources { _dir: dir, store, keys }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    cost: Cost,
    /// Unscaled backlog in seconds (0, 3,600, 10,800).
    backlog_s: f64,
    /// Modeled seconds of continuing arrivals.
    arrivals_s: f64,
    /// `Some`: a tight process memory cap (bytes). The working budget and
    /// the merge decode window both derive from it, as in the cell
    /// constructor (`buffer_budget_for`, `merge::set_memory_budget`).
    memory_cap: Option<u64>,
    fail_l0_data: &'static [usize],
    shape: Shape,
    /// Backlog durations are divided by this (see the module docs).
    scale: f64,
}

impl Case {
    fn backlog_objects(&self) -> usize {
        ((self.backlog_s / self.scale) * OFFERED_EPS / self.shape.rows_per_object as f64).round() as usize
    }
    fn arrival_objects(&self) -> usize {
        ((self.arrivals_s * OFFERED_EPS) / self.shape.rows_per_object as f64).round() as usize
    }
    fn objects(&self) -> usize {
        self.backlog_objects() + self.arrival_objects()
    }
    /// B / (900 - 300), scaled.
    fn deadline_s(&self) -> f64 {
        self.backlog_s * OFFERED_EPS / (REQUIRED_SERVICE_EPS - OFFERED_EPS) / self.scale
    }
}

#[derive(Debug, Default, Clone)]
struct Run {
    rows: u64,
    objects: usize,
    /// Modeled seconds until the lag first fell to `CAUGHT_UP_LAG_MS`.
    caught_up_s: Option<f64>,
    rows_at_caught_up: u64,
    /// Commits (one ack call per flush) as `(modeled s, committed rows, acks)`.
    commits: Vec<(f64, u64, usize)>,
    /// Largest lag of the oldest unacknowledged notice (modeled seconds).
    max_lag_s: f64,
    /// Most live L0 parts at once, and the oldest unmerged L0 age (modeled
    /// s): merges must keep running beside catch-up (bounded yields).
    peak_l0_parts: usize,
    max_unmerged_l0_age_s: f64,
    /// Merges committed, and admitted batches left unstamped (prevalence
    /// pending): catch-up must not starve either (bounded yields).
    merges: u64,
    unstamped_batches: u64,
    /// Age-due seals deferred beside an unfinished flight (step 3a).
    seals_deferred: u64,
    seals_first: u64,
    /// The longest one buffer's age-due seal stayed deferred (modeled s).
    seal_deferred_max_s: f64,
    drained_s: f64,
    peak_flights: usize,
    peak_puts_in_flight: usize,
    peak_outstanding_ranges: usize,
    flushes_pipelined: u64,
    adds: usize,
    l0_puts: usize,
    other_part_puts: usize,
    log_puts: usize,
    put_bytes: u64,
    put_conflicts: usize,
    gets: usize,
    lists: usize,
    deletes: usize,
    range_calls: usize,
    ack_calls: usize,
    total_requests: usize,
    injected_failures: usize,
    l0_data_puts: usize,
    owner_calls: usize,
    pacer_wait_s: f64,
    tick_errors: usize,
}

impl Run {
    fn service_eps(&self) -> Option<f64> {
        self.caught_up_s.filter(|s| *s > 0.0).map(|s| self.rows_at_caught_up as f64 / s)
    }
    /// The steady-state window: from the first backlog commit to the commit
    /// at catch-up, `(flushes, committed rows / modeled s)`. The first
    /// flush's fill and commit latency is outside it.
    fn steady(&self) -> Option<(usize, f64)> {
        let caught = self.caught_up_s?;
        let (t0, r0, a0) = *self.commits.first()?;
        let &(t1, r1, a1) = self.commits.iter().rev().find(|(t, _, _)| *t <= caught)?;
        (t1 > t0).then(|| (a1 - a0, (r1 - r0) as f64 / (t1 - t0)))
    }
    /// The ingest-path provider writes and queue calls (L0 parts, the part
    /// log, edge ranges and acks) per committed row.
    fn ingest_requests_per_row(&self) -> f64 {
        (self.l0_puts + self.adds + self.range_calls + self.ack_calls) as f64 / self.rows.max(1) as f64
    }
    fn report(&self, label: &str, case: &Case) -> String {
        format!(
            "{label} cost={} shape={} backlog={}s/scale{} offered={OFFERED_EPS}EPS objects={} rows={} rows_per_add={} peak_l0={} max_l0_age_s={:.0} merges={} unstamped={} seals_deferred={} seals_first={} seal_deferred_max_s={:.1} caught_up_s={:?} (deadline {:.1}) max_lag_s={:.1} \
             service_eps={:?} net_drain_eps={:?} steady={:?} drained_s={:.1} flights_peak={} puts_in_flight_peak={} ranges_peak={} pipelined={} \
             adds={} l0_puts={} other_part_puts={} log_puts={} put_bytes={} put_conflicts={} gets={} lists={} deletes={} \
             range_calls={} ack_calls={} total_requests={} ingest_requests_per_row={:.5} failures={} l0_data_puts={} owner_calls={} pacer_wait_s={:.1} tick_errors={}",
            case.cost.name, case.shape.name, case.backlog_s, case.scale, self.objects, self.rows,
            self.rows / self.adds.max(1) as u64, self.peak_l0_parts, self.max_unmerged_l0_age_s, self.merges, self.unstamped_batches, self.seals_deferred, self.seals_first, self.seal_deferred_max_s, self.caught_up_s.map(|s| (s * 10.0).round() / 10.0),
            case.deadline_s(), self.max_lag_s, self.service_eps().map(|v| v.round()), self.service_eps().map(|v| (v - OFFERED_EPS).round()),
            self.steady().map(|(flushes, eps)| (flushes, eps.round())),
            self.drained_s, self.peak_flights, self.peak_puts_in_flight, self.peak_outstanding_ranges, self.flushes_pipelined,
            self.adds, self.l0_puts, self.other_part_puts, self.log_puts, self.put_bytes, self.put_conflicts, self.gets,
            self.lists, self.deletes, self.range_calls, self.ack_calls, self.total_requests, self.ingest_requests_per_row(),
            self.injected_failures, self.l0_data_puts, self.owner_calls, self.pacer_wait_s, self.tick_errors,
        )
    }
}

/// Every (uid) in the live set, read from the local store (uncounted).
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

async fn logged_adds(parts: &LocalObjectStore) -> Vec<Vec<String>> {
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

/// One run on the paused clock: the backlog is delivered up front (notified
/// in the past at 300 EPS), arrivals continue at 300 EPS for
/// `case.arrivals_s`, and the loop runs like the cell's (`tick`, then wait
/// for a finished flight or 1 s) until everything is acknowledged.
async fn run(case: Case, policy: Policy, sources: &Sources) -> Run {
    let objects = case.objects();
    assert!(objects <= sources.keys.len());
    let backlog = case.backlog_objects();
    let dir = tempfile::tempdir().unwrap();
    let store: &'static ModeledStore = Box::leak(Box::new(ModeledStore::new(&dir.path().join("parts"), case.cost,
        case.fail_l0_data.iter().copied().collect())));
    let reader = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-signer-4539", SigningKey::from_bytes(&[45; 32])).unwrap()));
    let queue = ModelQueue {
        spool: SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap(), parts: &reader, sources: &sources.store,
        ranges: if policy == Policy::Serial { 1 } else { 2 },
        issued: Default::default(), keys: Default::default(), unacked: Default::default(),
        range_calls: AtomicUsize::new(0), ack_calls: AtomicUsize::new(0), acked: AtomicUsize::new(0), peak_outstanding: AtomicUsize::new(0),
    };
    let mut cfg = IngestConfig::new(TENANT, dir.path().join("work"));
    // The cell's settings (part_ingest/cell.rs) that matter here.
    cfg.background_merges = true;
    cfg.prevalence_enabled = false;
    // The merge decode window is process-wide: a capped run holds the
    // write side so no concurrently running case sees its window, and puts
    // the default back when it ends.
    let _window = MergeWindow::hold(case.memory_cap);
    if let Some(cap) = case.memory_cap {
        cfg.buffer_budget_bytes = buffer_budget_for(cap);
    }
    match policy {
        Policy::Serial => {
            cfg.flush_depth = 1;
            cfg.commit_when_ready = false;
        }
        Policy::Bounded => assert!(cfg.flush_depth == 2 && cfg.commit_when_ready, "production constructor defaults"),
    }
    let base_ms = EVENT0_MS + arrival_ms(backlog, case.shape) as i64;
    let mut ingestor = Ingestor::open(cfg, store, &sources.store, &queue, signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), base_ms).await.unwrap();
    ingestor.set_background_store(store);
    ingestor.set_background_signer(signer);
    let wake = Arc::new(tokio::sync::Notify::new());
    ingestor.set_flight_wake(wake.clone());
    let deliver = |index: usize| {
        let notified_ms = EVENT0_MS + arrival_ms(index, case.shape) as i64;
        let key = &sources.keys[index];
        queue.spool.deliver(&SourceNotice {
            tenant_id: TENANT.into(), key: key.clone(), version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
            notified_at_ms: notified_ms,
        }).unwrap();
        queue.unacked.lock().unwrap().insert(key.clone(), notified_ms);
    };
    for index in 0..backlog {
        deliver(index);
    }
    let start = tokio::time::Instant::now();
    let mut next = backlog;
    let mut out = Run { objects, ..Run::default() };
    let mut last_occupancy_s = u64::MAX;
    let hard_cap = Duration::from_secs_f64((case.arrivals_s + case.deadline_s()) * 4.0 + 600.0);
    loop {
        let tick_ms = base_ms + start.elapsed().as_millis() as i64;
        while next < objects && EVENT0_MS + arrival_ms(next, case.shape) as i64 <= tick_ms {
            deliver(next);
            next += 1;
        }
        if ingestor.tick(tick_ms).await.is_err() {
            out.tick_errors += 1;
            assert!(out.tick_errors <= 64, "{}", out.report("tick keeps failing", &case));
        }
        // Measure AFTER the tick: the tick that commits (its inline build,
        // publication and append) counts toward catch-up, lag and drain.
        let elapsed = start.elapsed();
        let now_ms = base_ms + elapsed.as_millis() as i64;
        // Arrivals during the tick are pending now (they count toward lag).
        while next < objects && EVENT0_MS + arrival_ms(next, case.shape) as i64 <= now_ms {
            deliver(next);
            next += 1;
        }
        let health = ingestor.health();
        let acks = queue.ack_calls.load(Ordering::SeqCst);
        if out.commits.last().is_none_or(|(_, _, last)| *last != acks) && health.rows_committed_total > 0 {
            out.commits.push((elapsed.as_secs_f64(), health.rows_committed_total, acks));
            if case.shape.rows_per_object != SMALL.rows_per_object {
                eprintln!("NAN4539-PROGRESS {policy:?} t={:.1} rows={} acks={acks} lag_s={:.0} flights={} buffered_rows={} l0={}",
                    elapsed.as_secs_f64(), health.rows_committed_total, health.lag_ms as f64 / 1e3, health.flushes_in_flight,
                    health.buffered_rows, health.live_parts_by_level.get("l0").copied().unwrap_or(0));
            }
        }
        // Working-set occupancy, once per modeled second at most (with the
        // finished-flight wake many ticks share one instant).
        if case.shape.rows_per_object != SMALL.rows_per_object && elapsed.as_secs() != last_occupancy_s {
            last_occupancy_s = elapsed.as_secs();
            let snapshot = ingestor.diagnostics().snapshot();
            let o = &snapshot["occupancy"];
            eprintln!("NAN4539-OCCUPANCY {policy:?} t={:.1} depth={} filling_rows={} filling_objects={} filling_mb={:.0} flight_rows={} \
                flight_reserved_mb={:.0} merge_reserved_mb={:.0} working_mb={:.0} budget_mb={:.0} exhausted={} may_seal_beside={} queue={}",
                elapsed.as_secs_f64(), o["effective_flush_depth"], o["filling_rows"], o["filling_objects"],
                o["filling_arrow_bytes"].as_f64().unwrap_or(0.0) / 1e6, o["flight_rows"],
                o["flight_reserved_bytes"].as_f64().unwrap_or(0.0) / 1e6, o["merge_reserved_bytes"].as_f64().unwrap_or(0.0) / 1e6,
                o["working_reserved_bytes"].as_f64().unwrap_or(0.0) / 1e6, o["working_budget_bytes"].as_f64().unwrap_or(0.0) / 1e6,
                o["memory_budget_exhausted"], o["may_seal_beside_flights"], snapshot["queue_sample"]);
        }
        out.peak_flights = out.peak_flights.max(health.flushes_in_flight);
        out.peak_l0_parts = out.peak_l0_parts.max(health.live_parts_by_level.get("l0").copied().unwrap_or(0));
        out.max_unmerged_l0_age_s = out.max_unmerged_l0_age_s.max(health.oldest_unmerged_l0_age_ms.max(0) as f64 / 1_000.0);
        let lag = queue.unacked.lock().unwrap().values().min().map_or(0, |oldest| (now_ms - oldest).max(0) as u64);
        out.max_lag_s = out.max_lag_s.max(lag as f64 / 1_000.0);
        // The source frontier passed the outage: every backlog notice acked.
        let frontier_passed = backlog == 0 || queue.unacked.lock().unwrap().keys().next()
            .is_none_or(|oldest| oldest.as_str() > sources.keys[backlog - 1].as_str());
        if out.caught_up_s.is_none() && frontier_passed && lag <= CAUGHT_UP_LAG_MS {
            out.caught_up_s = Some(elapsed.as_secs_f64());
            out.rows_at_caught_up = health.rows_committed_total;
        }
        if next == objects && queue.unacked.lock().unwrap().is_empty() && health.flushes_in_flight == 0 && health.buffered_rows == 0 {
            out.drained_s = elapsed.as_secs_f64();
            break;
        }
        assert!(elapsed < hard_cap, "{} last_commit={:?} delivered={next}/{objects} pending_notices={} buffered_rows={} \
            flushes_in_flight={} merge_backlog={} live_parts={:?} stalled={}",
            out.report("never drained", &case), out.commits.last(), health.pending_notices, health.buffered_rows,
            health.flushes_in_flight, health.merge_backlog, health.live_parts_by_level, health.stalled);
        tokio::select! {
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    let health = ingestor.health().clone();
    (out.seals_deferred, out.seals_first) = ingestor.seals_deferred();
    drop(ingestor);
    out.rows = health.rows_committed_total;
    out.merges = health.merges_total;
    out.unstamped_batches = health.prevalence_unstamped_batches_total;
    out.flushes_pipelined = health.flushes_pipelined_total;
    out.seal_deferred_max_s = health.seal_deferred_max_ms as f64 / 1_000.0;
    out.peak_flights = out.peak_flights.max(health.flushes_in_flight_peak);
    out.peak_puts_in_flight = store.peak_in_flight.load(Ordering::SeqCst);
    out.peak_outstanding_ranges = queue.peak_outstanding.load(Ordering::SeqCst);
    out.l0_puts = store.l0_puts.load(Ordering::SeqCst);
    out.other_part_puts = store.other_part_puts.load(Ordering::SeqCst);
    out.log_puts = store.log_puts.load(Ordering::SeqCst);
    out.put_bytes = store.put_bytes.load(Ordering::SeqCst);
    out.put_conflicts = store.put_conflicts.load(Ordering::SeqCst);
    out.gets = store.gets.load(Ordering::SeqCst);
    out.lists = store.lists.load(Ordering::SeqCst);
    out.deletes = store.deletes.load(Ordering::SeqCst);
    out.total_requests = store.total_requests();
    out.injected_failures = store.failures.load(Ordering::SeqCst);
    out.l0_data_puts = store.l0_data_puts.load(Ordering::SeqCst);
    out.owner_calls = store.owner_calls.load(Ordering::SeqCst);
    out.pacer_wait_s = store.pacer_wait_us.load(Ordering::SeqCst) as f64 / 1e6;
    out.range_calls = queue.range_calls.load(Ordering::SeqCst);
    out.ack_calls = queue.ack_calls.load(Ordering::SeqCst);
    // Correctness: every row exactly once, each source consumed by one add,
    // every notice acknowledged once.
    let adds = logged_adds(&reader).await;
    out.adds = adds.len();
    let mut consumed = HashSet::new();
    for key in adds.iter().flatten() {
        assert!(consumed.insert(key.clone()), "{key} consumed by two adds");
    }
    assert_eq!(consumed.len(), objects, "every source consumed once: {}", out.report("consumed", &case));
    assert_eq!(queue.acked.load(Ordering::SeqCst), objects, "every notice acked exactly once");
    let uids = live_uids(&reader).await;
    let unique = uids.iter().collect::<HashSet<_>>();
    assert_eq!(unique.len(), uids.len(), "a uid appears twice in the live set");
    assert_eq!(uids.len(), objects * case.shape.rows_per_object, "rows lost or gained");
    assert_eq!(out.rows, (objects * case.shape.rows_per_object) as u64);
    // Bounds that hold for every case.
    assert!(out.peak_flights <= if policy == Policy::Serial { 1 } else { 2 }, "{}", out.report("flight bound", &case));
    // NAN-4539 step 3a, bounded yield: an age-due seal deferred beside an
    // unfinished flight seals once a slot frees, i.e. by the next commit. It
    // never waits longer than the longest wait for a commit (the first, or
    // the widest gap between two) plus one tick (the loop sleeps <= 1 s).
    let commit_wait_s = out.commits.iter().map(|(t, _, _)| *t).fold((0.0_f64, 0.0_f64), |(widest, last), t| (widest.max(t - last), t)).0;
    assert!(out.seal_deferred_max_s <= commit_wait_s + 2.0, "a deferred seal waited {:.1}s, the widest commit wait is {:.1}s: {}",
        out.seal_deferred_max_s, commit_wait_s, out.report("deferral unbounded", &case));
    assert!(out.peak_puts_in_flight <= ENVELOPE, "the shared write envelope");
    out
}

fn report(case: &Case, serial: &Run, bounded: &Run) {
    eprintln!("NAN4539-MODELED {}", serial.report("serial", case));
    eprintln!("NAN4539-MODELED {}", bounded.report("bounded", case));
}

/// Gates shared by every successful healthy pair: bounded overlap never
/// costs more ingest-path requests per committed row than the serial
/// baseline (beyond one flush's worth for a different tail cut), never
/// adds a part write per flush, and never serves slower.
fn assert_cost_and_order(case: &Case, serial: &Run, bounded: &Run) {
    let one_flush = 2.0 * (serial.l0_puts as f64 / serial.adds.max(1) as f64 + 3.0);
    assert!(
        bounded.ingest_requests_per_row() <= serial.ingest_requests_per_row() + one_flush / bounded.rows as f64,
        "bounded overlap costs more requests per committed row:\n{}\n{}", serial.report("serial", case), bounded.report("bounded", case)
    );
    assert!(bounded.l0_puts as f64 / bounded.adds as f64 <= serial.l0_puts as f64 / serial.adds as f64 + 1.0,
        "a bounded flush writes more part objects than a serial one");
    assert_eq!(bounded.put_conflicts, 0, "a healthy bounded run re-PUTs nothing");
    assert_eq!(bounded.tick_errors, 0);
    assert_eq!(serial.tick_errors, 0);
}

/// A backlog case at the smoke scale (60).
fn backlog_case(cost: Cost, backlog_s: f64) -> Case {
    scaled_case(cost, backlog_s, SMOKE_SCALE)
}

/// A backlog case at `scale`; arrivals continue for 1.5 deadlines.
fn scaled_case(cost: Cost, backlog_s: f64, scale: f64) -> Case {
    let deadline = backlog_s * OFFERED_EPS / (REQUIRED_SERVICE_EPS - OFFERED_EPS) / scale;
    Case { cost, backlog_s, arrivals_s: (deadline * 1.5).max(60.0), memory_cap: None, fail_l0_data: &[], shape: SMALL, scale }
}

/// Bounded drains no slower than serial, give or take the tail seal. Once
/// arrivals stop, the last partial buffer seals on its age cap
/// (`DEFAULT_FLUSH_MAX_AGE_MS`), measured from its first row; where that row
/// fell depends on where the earlier cuts landed, which differs between the
/// policies. So drain-end can differ by up to one age cap at any IO cost
/// (seen at ZERO cost: serial 64.8 s, bounded 70.8 s, while bounded caught up
/// first, 7.9 s vs 12.6 s). Catch-up is compared strictly where it is gated.
fn assert_drains_no_slower(case: &Case, serial: &Run, bounded: &Run) {
    let tail_seal_s = DEFAULT_FLUSH_MAX_AGE_MS as f64 / 1_000.0;
    assert!(bounded.drained_s <= serial.drained_s + tail_seal_s, "{}\n{}",
        serial.report("serial", case), bounded.report("bounded", case));
}

async fn pair(case: Case) -> (Run, Run) {
    let sources = sources(case.objects(), case.shape);
    let serial = run(case, Policy::Serial, &sources).await;
    let bounded = run(case, Policy::Bounded, &sources).await;
    report(&case, &serial, &bounded);
    (serial, bounded)
}

/// Empty backlog: 300 EPS steady arrivals keep up under every cost, the
/// bounded path costs no more per row and holds ordering.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn steady_300_eps_without_backlog_keeps_up_at_every_modeled_cost() {
    for cost in [ZERO, ESTIMATE, THREE_X] {
        let case = Case { cost, backlog_s: 0.0, arrivals_s: 60.0, memory_cap: None, fail_l0_data: &[], shape: SMALL, scale: SMOKE_SCALE };
        let (serial, bounded) = pair(case).await;
        assert_cost_and_order(&case, &serial, &bounded);
        // Caught up at the first measurement: within the first tick, which
        // also pays the fresh work dir's one-time bronze quarantine restore
        // LIST (NAN-4554, one modeled request: 0.1 s at the estimate cost).
        assert!(bounded.caught_up_s.is_some_and(|s| s <= 1.0), "{}", bounded.report("fell behind without a backlog", &case));
    }
}

/// Per-case scales for the throughput gates: each backlog is 270,000 rows,
/// so at least [`MIN_STEADY_FLUSHES`] commit in steady state before
/// catch-up. (Step 2 used 180,000 rows at scales 6/18; Step 3a's larger
/// catch-up flushes, ~13k rows, cut that to 9 steady flushes.)
const ONE_HOUR_SCALE: f64 = 4.0;
const THREE_HOUR_SCALE: f64 = 12.0;
/// With no IO cost each flush is cut larger (admission outruns the age
/// cap), so 180,000 rows gave only 8 steady flushes (run8: 2,643 rows/s
/// over 8); 324,000 rows (scale 10) spans at least ten.
const ZERO_COST_THREE_HOUR_SCALE: f64 = 10.0;

/// The convergence gate: the scaled backlog clears within B/(900-300), and
/// total service over the steady-state window (first backlog commit to the
/// commit at catch-up, at least [`MIN_STEADY_FLUSHES`] flushes) is at least
/// 900 rows/s (3x offered).
fn assert_converges(case: &Case, run: &Run) {
    let caught = run.caught_up_s.unwrap_or_else(|| panic!("{}", run.report("never caught up", case)));
    assert!(caught <= case.deadline_s(), "{}", run.report("missed the catch-up deadline", case));
    let (flushes, eps) = run.steady().unwrap_or_else(|| panic!("{}", run.report("no steady-state window", case)));
    assert!(flushes >= MIN_STEADY_FLUSHES, "{}", run.report("too few flushes for a steady-state rate", case));
    assert!(eps >= REQUIRED_SERVICE_EPS, "{}", run.report("steady-state service below 900 rows/s", case));
}

/// SMOKE, not a throughput gate: at the smoke scale a "1h" backlog is
/// 18,000 rows, two or three flushes, so the first flush's fill and commit
/// latency dominates and a second flight has nothing to overlap with; a
/// rate over it measures that latency, not service. It checks what such a
/// short backlog can show: the deadline is met, bounded catches up no later
/// than serial and drains no later than serial plus one tail seal
/// ([`assert_drains_no_slower`]), and (in `run`) every row lands exactly
/// once, in order. The
/// 900 rows/s bar is enforced on the representative 1h run below.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_hour_backlog_smoke_meets_its_deadline_and_beats_serial() {
    for cost in [ZERO, ESTIMATE] {
        let case = backlog_case(cost, 3_600.0);
        let (serial, bounded) = pair(case).await;
        assert_cost_and_order(&case, &serial, &bounded);
        let caught = bounded.caught_up_s.unwrap_or_else(|| panic!("{}", bounded.report("never caught up", &case)));
        assert!(caught <= case.deadline_s(), "{}", bounded.report("missed the catch-up deadline", &case));
        assert!(bounded.caught_up_s <= serial.caught_up_s, "{}\n{}", serial.report("serial", &case), bounded.report("bounded", &case));
        assert_drains_no_slower(&case, &serial, &bounded);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_hour_backlog_converges_at_estimated_modeled_cost() {
    let case = scaled_case(ESTIMATE, 3_600.0, ONE_HOUR_SCALE);
    let (serial, bounded) = pair(case).await;
    assert_cost_and_order(&case, &serial, &bounded);
    assert_eq!(bounded.peak_flights, 2, "{}", bounded.report("the backlog overlaps two flights", &case));
    assert_converges(&case, &bounded);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn three_hour_backlog_converges_at_estimated_modeled_cost() {
    let case = scaled_case(ESTIMATE, 10_800.0, THREE_HOUR_SCALE);
    let (serial, bounded) = pair(case).await;
    assert_cost_and_order(&case, &serial, &bounded);
    assert_eq!(bounded.peak_flights, 2, "{}", bounded.report("the backlog overlaps two flights", &case));
    assert_converges(&case, &bounded);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn three_hour_backlog_converges_at_zero_modeled_cost() {
    let case = scaled_case(ZERO, 10_800.0, ZERO_COST_THREE_HOUR_SCALE);
    let (serial, bounded) = pair(case).await;
    assert_cost_and_order(&case, &serial, &bounded);
    assert_converges(&case, &bounded);
}

/// 3x every estimate (the p95 stand-in), at the representative scales:
/// reported honestly, NOT gated on 900 (the serial commit stage alone caps
/// it lower, see the README); must stay correct, ordered, bounded, drain no
/// slower than serial and never cost more per row.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_and_three_hour_backlogs_at_three_times_the_modeled_cost_stay_bounded_and_drain() {
    for (backlog_s, scale) in [(3_600.0, ONE_HOUR_SCALE), (10_800.0, THREE_HOUR_SCALE)] {
        let case = scaled_case(THREE_X, backlog_s, scale);
        let (serial, bounded) = pair(case).await;
        assert_cost_and_order(&case, &serial, &bounded);
        assert_drains_no_slower(&case, &serial, &bounded);
    }
}

/// A tight working budget (a 533 MiB cell): before Step 3a a second seal's
/// writer reservation never fit beside the first flight, so it fell back to
/// one flight. With writers reserved for the parts a plan writes and a
/// published flight charged only its retained rows, a second small flight
/// fits. The gate is what the budget must still guarantee: at most the
/// configured depth, catch-up within the deadline and no later than
/// serial, a drain no slower than serial, in order, exactly once (in `run`).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_tight_memory_budget_stays_within_depth_and_still_drains() {
    let mut case = backlog_case(ESTIMATE, 10_800.0);
    // A 533 MiB cell: a 160 MiB working budget (30%), below four 48 MiB L0
    // writers, so the first flight takes the most writers that fit and a
    // second seal's own writer can never fit beside it; its merge decode
    // window is 2,730 rows (27 MiB), as the cell constructor sizes it.
    case.memory_cap = Some(533 * 1024 * 1024);
    let sources = sources(case.objects(), case.shape);
    let serial = run(case, Policy::Serial, &sources).await;
    eprintln!("NAN4539-MODELED {}", serial.report("serial-tight-budget", &case));
    let bounded = run(case, Policy::Bounded, &sources).await;
    eprintln!("NAN4539-MODELED {}", bounded.report("bounded-tight-budget", &case));
    assert!(bounded.peak_flights <= 2, "{}", bounded.report("tight budget", &case));
    let caught = bounded.caught_up_s.unwrap_or_else(|| panic!("{}", bounded.report("tight budget never caught up", &case)));
    assert!(caught <= case.deadline_s(), "{}", bounded.report("tight budget missed the deadline", &case));
    assert!(serial.caught_up_s.is_none_or(|serial_s| caught <= serial_s), "{}", bounded.report("tight budget slower than serial", &case));
    assert_drains_no_slower(&case, &serial, &bounded);
}

/// Transient owner failures on L0 data PUTs (the same ordinals for both
/// policies): both recover exactly once, in order; the extra requests are
/// bounded by one publication per failure.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn transient_publication_failures_replay_with_bounded_extra_cost() {
    let mut case = backlog_case(ESTIMATE, 10_800.0);
    case.fail_l0_data = &[1, 3, 5];
    let (serial, bounded) = pair(case).await;
    let healthy = {
        let mut case = case;
        case.fail_l0_data = &[];
        let sources = sources(case.objects(), case.shape);
        run(case, Policy::Bounded, &sources).await
    };
    eprintln!("NAN4539-MODELED {}", healthy.report("bounded-healthy-reference", &case));
    for failed in [&serial, &bounded] {
        assert_eq!(failed.injected_failures, case.fail_l0_data.len(), "{}", failed.report("injected", &case));
        assert!(failed.tick_errors <= case.fail_l0_data.len() * 2, "{}", failed.report("tick errors", &case));
    }
    // A failed publication retries its flight's objects (existing ones are
    // conflicts, never rewritten): at most one publication's objects each.
    let per_publication = (healthy.l0_puts + healthy.other_part_puts) / healthy.adds.max(1) + 2;
    let extra = bounded.l0_puts as i64 + bounded.other_part_puts as i64 - (healthy.l0_puts + healthy.other_part_puts) as i64;
    assert!(extra <= (case.fail_l0_data.len() * per_publication) as i64,
        "replay cost {extra} exceeds {} publications:\n{}\n{}", case.fail_l0_data.len(), healthy.report("healthy", &case), bounded.report("failed", &case));
}

/// The offline physical benchmark (explicitly invoked, see the README): the
/// same serial/bounded pair on the real clock and local disk with no modeled
/// IO delay, so only real CPU and disk time count. Wall-clock rows/s on this
/// host; not a live EPS claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn physical_wall_clock_benchmark() {
    let case = Case { cost: ZERO, backlog_s: 3_600.0, arrivals_s: 30.0, memory_cap: None, fail_l0_data: &[], shape: SMALL, scale: SMOKE_SCALE };
    let sources = sources(case.objects(), case.shape);
    for policy in [Policy::Serial, Policy::Bounded] {
        let started = std::time::Instant::now();
        let result = run(case, policy, &sources).await;
        let wall = started.elapsed().as_secs_f64();
        eprintln!("NAN4539-PHYSICAL {policy:?} rows={} wall_s={wall:.3} wall_rows_per_s={:.0} flights_peak={} \
            (local disk, real CPU, no modeled IO; not a live EPS claim)", result.rows, result.rows as f64 / wall, result.peak_flights);
    }
}

/// Step 3 probe: large-tenant-shaped sources (728-row segments, ~5.6 KB rows) in a
/// large-tenant-sized cell (its 5.63 GB ingest cap) at 3x the per-row costs.
/// Reported, not gated: it shows what bounds a flush's rows.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore]
async fn step3_probe_segment_shape_three_x() {
    let mut case = scaled_case(ROW_THREE_X, 10_800.0, 12.0);
    case.shape = SEGMENT;
    case.memory_cap = Some(B12_INGEST_MEMORY_CAP);
    let (serial, bounded) = pair(case).await;
    eprintln!("NAN4539-STEP3-PROBE commits(bounded) {:?}", bounded.commits);
    eprintln!("NAN4539-STEP3-PROBE commits(serial) {:?}", serial.commits);
}

/// large-tenant-shaped flushes are ~65k rows (the `FLUSH_MAX_ROWS` cap), so a 3h
/// backlog spans [`MIN_STEADY_FLUSHES`] only at scale 4 (810,000 backlog
/// rows); scale 12 is 4-5 flushes, where the first flush's fill and commit
/// latency dominates the deadline.
const SEGMENT_THREE_HOUR_SCALE: f64 = 4.0;

/// NAN-4539 step 3 gate: large-tenant-shaped sources in a large-tenant-sized cell at 3x the
/// fitted per-row costs (`ROW_THREE_X`) clear a 3h backlog within 1.5h at
/// >= 900 rows/s steady service, with bounded yields: L0 stays bounded,
/// merges still commit, no admitted batch goes unstamped. Release only (the
/// 4 KB rows make a debug build several times slower):
/// `cargo test --release -p nanosiem-lake-worker --test nan4539_flush_convergence -- --ignored step3_`
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore]
async fn step3_segment_shape_three_x_three_hour_backlog_converges() {
    let mut case = scaled_case(ROW_THREE_X, 10_800.0, SEGMENT_THREE_HOUR_SCALE);
    case.shape = SEGMENT;
    case.memory_cap = Some(B12_INGEST_MEMORY_CAP);
    let (serial, bounded) = pair(case).await;
    eprintln!("NAN4539-STEP3-GATE commits(bounded) {:?}", bounded.commits);
    assert_converges(&case, &bounded);
    assert_cost_and_order(&case, &serial, &bounded);
    assert!(bounded.peak_l0_parts <= 64, "{}", bounded.report("L0 unbounded during catch-up", &case));
    assert!(bounded.merges > 0, "{}", bounded.report("merges starved", &case));
    // Bounded yields: catch-up never leaves an L0 part unmerged longer than
    // the serial policy does on the same backlog and cost.
    assert!(bounded.max_unmerged_l0_age_s <= serial.max_unmerged_l0_age_s, "{}\n{}",
        serial.report("serial", &case), bounded.report("L0 waited longer for its merge than serial", &case));
    // Vacuous in this model (prevalence is disabled, its cost charged on the
    // `add` append); kept so a model that enables it gates it.
    assert_eq!(bounded.unstamped_batches, 0, "{}", bounded.report("admission outran prevalence", &case));
}

/// Reported, not gated: the step 3 gate with prevalence fully linear in
/// rows (`ROW_THREE_X_LINEAR_PREVALENCE`, no fixed part): the conservative
/// bound if the large tenant's per-flush fit (r = 0.11) understates the row term.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore]
async fn step3_segment_shape_linear_prevalence_report() {
    let mut case = scaled_case(ROW_THREE_X_LINEAR_PREVALENCE, 10_800.0, SEGMENT_THREE_HOUR_SCALE);
    case.shape = SEGMENT;
    case.memory_cap = Some(B12_INGEST_MEMORY_CAP);
    let (_, bounded) = pair(case).await;
    eprintln!("NAN4539-STEP3-LINEAR commits(bounded) {:?}", bounded.commits);
}
