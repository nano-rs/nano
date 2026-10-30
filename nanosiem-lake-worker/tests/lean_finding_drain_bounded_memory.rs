// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4691: the drain-only detect process (256 MiB on pooled cells, now
//! 1 GiB: NAN-4690) was SIGKILLed by its cgroup in a loop on FP ops
//! (2026-10-27). Auditing its memory: the finding drain's log view and its
//! replay proof both folded a full `LiveSet` (every part added, removed or
//! seen inside the 48 h id memory), so the drain's memory grew with the
//! tenant's part-log history, not with the findings it delivers. On a
//! 1 TB/day tenant (no checkpoint fits one log object, ~200k entries inside
//! the horizon) that alone exceeds the drain's budget.
//!
//! Production path: the drain (`drain_pass`, a tenant-bound RLS principal)
//! against the production ingest gate (`FindingGate` over `Ingestor`, on its
//! own runtime like the cell's separate ingest process), over a part log of
//! [`HISTORY`] entries whose parts all sit inside the id memory window.
//! The drain sees no usable checkpoint, so its log view catches up from
//! genesis on every pass. Every pass, including a replay proof that must
//! start at genesis (a SIGKILLed attempt's receipt whose best-effort floor
//! was never written), stays under
//! [`DRAIN_PEAK_BOUND`] of heap on the drain's threads, which a `LiveSet`
//! fold of the same log exceeds. A receipt whose proof was cut after the
//! scan resumes from its floor instead of re-scanning from genesis, and
//! every finding is consumed by exactly one `Add`.
//!
//! Run against a disposable PostgreSQL server with NANO_RISK_TEST_PG set to
//! its loopback administrator URL (`postgres://postgres@127.0.0.1:<port>/risktest`).
//! `NAN4691_HISTORY` overrides the history length (default 200,000).

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_gate::{FindingGate, FindingGateConfig};
use nanosiem_lake_worker::part_ingest::finding_floors::floor_prefix;
use nanosiem_lake_worker::part_ingest::finding_outbox::{drain_pass, FindingReceipt};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, FindingAppendContext, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::format::{LogKeys, PartId};
use nanosiem_lake_worker::parts::levels::Level;
use nanosiem_lake_worker::parts::part_log::{LiveSet, LocalObjectStore, LogEntry, LogOp, ObjectStore, PartLogWriter, PartRef, SourceRef, WriteHints};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sqlx::postgres::PgPoolOptions;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

const A: &str = "00000000-0000-4000-8000-000000004691";
const DB: &str = "risktest_finding_drain_bounded";
const ROLE: &str = "finding_drain_bounded_a";
/// Entries in the log before the first finding (ops had ~60.6k; a 1 TB/day
/// tenant appends this many inside the 48 h id memory window).
const HISTORY: u64 = 200_000;
/// Heap high-water mark of one drain pass on the drain's own threads. A
/// `LiveSet` folded over [`HISTORY`] entries is several times this.
const DRAIN_PEAK_BOUND: isize = 64 << 20;
/// What a proof resumed from its floor may read beyond the drain view's own
/// catch-up: a few fetch windows (as in NAN-4656).
const PROOF_READ_BOUND: usize = 6 * 32;

// ---------------------------------------------------------------------------
// Heap accounting scoped to the drain's threads
// ---------------------------------------------------------------------------

struct DrainHeap;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static TRACKED: Cell<bool> = const { Cell::new(false) };
}

fn tracked() -> bool {
    TRACKED.try_with(Cell::get).unwrap_or(false)
}

unsafe impl GlobalAlloc for DrainHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && tracked() {
            let live = LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed) + layout.size() as isize;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && tracked() {
            let live = LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed) + layout.size() as isize;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        if tracked() {
            LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() && tracked() {
            let delta = new_size as isize - layout.size() as isize;
            let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: DrainHeap = DrainHeap;

/// The drain's runtime: every worker and blocking thread is measured.
fn drain_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .on_thread_start(|| TRACKED.with(|flag| flag.set(true)))
        .on_thread_stop(|| TRACKED.with(|flag| flag.set(false)))
        .build()
        .unwrap()
}

/// Run `work` on the drain runtime and return its result with the heap
/// high-water mark above the live bytes at the start.
fn measured<T>(drain: &tokio::runtime::Runtime, work: impl std::future::Future<Output = T>) -> (T, isize) {
    TRACKED.with(|flag| flag.set(true));
    let start = LIVE.load(Ordering::Relaxed);
    PEAK.store(start, Ordering::Relaxed);
    let out = drain.block_on(work);
    let peak = PEAK.load(Ordering::Relaxed) - start;
    TRACKED.with(|flag| flag.set(false));
    (out, peak)
}

// ---------------------------------------------------------------------------
// The cell: object store, ingest role
// ---------------------------------------------------------------------------

/// Counts part-log entry GETs; cuts the next finding `Add` entry PUT before
/// it lands or after it lands (acknowledgement lost).
struct RollStore {
    inner: LocalObjectStore,
    entry_gets: AtomicUsize,
    cut_before: AtomicBool,
    cut_after: AtomicBool,
}

impl RollStore {
    fn take(&self) -> usize {
        self.entry_gets.swap(0, Ordering::SeqCst)
    }

    fn cut(&self, key: &str, bytes: &[u8], flag: &AtomicBool) -> anyhow::Result<()> {
        let add = key.contains("/log/entries/") && bytes.windows(12).any(|window| window == br#""kind":"add""#);
        if add && flag.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected: the detect process was SIGKILLed during the append");
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for RollStore {
    async fn modified_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
        self.inner.modified_ms(key).await
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        if key.contains("/log/entries/") {
            self.entry_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.cut(key, bytes, &self.cut_before)?;
        let created = self.inner.put_if_absent(key, bytes).await?;
        self.cut(key, bytes, &self.cut_after)?;
        Ok(created)
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.cut(key, bytes, &self.cut_before)?;
        let created = self.inner.put_if_absent_with(key, bytes, hints).await?;
        self.cut(key, bytes, &self.cut_after)?;
        Ok(created)
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

/// The drain's reads of the cell's store with no usable checkpoint: a live
/// set past one log object (~9k parts, a 1 TB/day tenant) is never
/// checkpointed, so a reader folds from genesis. Ingest keeps its own
/// in-memory set and is opened over the plain store.
struct NoCheckpoints(&'static RollStore);

#[async_trait]
impl ObjectStore for NoCheckpoints {
    async fn modified_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
        self.0.modified_ms(key).await
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.0.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        self.0.put_if_absent(key, bytes).await
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> anyhow::Result<bool> {
        self.0.put_if_absent_with(key, bytes, hints).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.0.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.0.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let snapshot = |key: &str| key.contains("/log/checkpoints/") && key.rsplit('/').next()
            .is_some_and(|name| name.len() == 25 && name.ends_with(".json") && name.as_bytes()[..20].iter().all(u8::is_ascii_digit));
        Ok(self.0.list(prefix).await?.into_iter().filter(|key| !snapshot(key)).collect())
    }
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// The cell's ingest role: the production gate over the production
/// ingestor, run on the ingest runtime (unmeasured), as the cell runs it in
/// a separate process.
struct IngestRole {
    runtime: tokio::runtime::Handle,
    gate: &'static FindingGate,
    ingestor: &'static tokio::sync::Mutex<Ingestor<'static>>,
    context: &'static FindingAppendContext<'static>,
    submits: AtomicUsize,
}

#[async_trait]
impl FindingAppendTransport for IngestRole {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        let request = FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch, schema: request.schema.clone(),
            parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
        };
        let (gate, ingestor, context) = (self.gate, self.ingestor, self.context);
        self.runtime.spawn(async move {
            let admitted = gate.admit()?;
            gate.append(admitted, ingestor, context, request, || chrono::Utc::now().timestamp_millis()).await
        }).await?
    }
}

async fn start_ingest(dir: &std::path::Path, store: &'static RollStore, queue: &'static SpoolQueue,
    signer: &'static LocalPartSigner, name: &str) -> IngestRole {
    let mut cfg = IngestConfig::new(A, dir.join(name));
    cfg.writer_epoch = 1;
    let ingestor = Ingestor::open(cfg, store, &store.inner, queue, signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    let context = leak(ingestor.finding_context());
    IngestRole {
        runtime: tokio::runtime::Handle::current(),
        gate: leak(FindingGate::new(FindingGateConfig::default())),
        ingestor: leak(tokio::sync::Mutex::new(ingestor)),
        context,
        submits: AtomicUsize::new(0),
    }
}

// ---------------------------------------------------------------------------
// The history and the outbox
// ---------------------------------------------------------------------------

fn part(n: u64, created_ms: i64, level: Level) -> PartRef {
    PartRef {
        request_hours: None,
        part_id: PartId::parse(&format!("{created_ms:013}-{n:016x}")).unwrap(),
        level, event_hour: 10, event_day: None, rows: 5, min_time_us: 1, max_time_us: 2,
        schema_fingerprint: "a".repeat(64), provenance_sha256: "b".repeat(64), merkle_root: "c".repeat(64),
        sorted: true, data_bytes: 10, row_groups: 1, data_files: 1,
    }
}

/// Seqs `1..=HISTORY` as ingest and compaction write them: an `Add` of one
/// L0 part, then a `Merge` folding it into the running output, so the live
/// set stays one part while every part stays in the id memory window. A
/// checkpoint at the head serves ingest; the drain reads the store through
/// [`NoCheckpoints`] and catches up from genesis, and a replay proof
/// without a floor starts at genesis too.
async fn write_history(store: &LocalObjectStore, history: u64, now_ms: i64) {
    let mut writer = PartLogWriter::open(store, A, 1, &seed_schema(), now_ms).await.unwrap();
    drop(writer);
    let keys = LogKeys::new(A).unwrap();
    let genesis = store.get(&keys.entry(0)).await.unwrap().unwrap();
    let format = LogEntry::parse_bytes(&genesis, A).unwrap().format;
    let mut prev = nanosiem_lake_worker::parts::sha256_hex(&genesis);
    let created = now_ms - 3_600_000;
    let mut merged: Option<PartId> = None;
    for seq in 1..=history {
        let op = if seq % 2 == 1 {
            LogOp::Add {
                parts: vec![part(seq, created, Level::L0)],
                consumed: vec![SourceRef { key: format!("bronze/h{seq}.parquet"), version: "1".into(), sha256: "d".repeat(64) }],
                edge_log: None,
            }
        } else {
            let output = part(seq, created, Level::Minute);
            let mut supersedes = vec![part(seq - 1, created, Level::L0).part_id];
            supersedes.extend(merged.replace(output.part_id.clone()));
            LogOp::Merge { output, supersedes }
        };
        let entry = LogEntry { format: format.clone(), tenant_id: A.into(), seq, prev_sha256: prev, writer_epoch: 1,
            appended_at_ms: created, op };
        let bytes = entry.to_bytes().unwrap();
        assert!(store.put_if_absent(&keys.entry(seq), &bytes).await.unwrap());
        prev = nanosiem_lake_worker::parts::sha256_hex(&bytes);
    }
    writer = PartLogWriter::open(store, A, 1, &seed_schema(), now_ms).await.unwrap();
    assert_eq!(writer.live().head().map(|head| head.0), Some(history));
    assert_eq!(writer.live().parts().count(), 1);
    writer.write_checkpoint(now_ms).await.unwrap();
}

/// What the old drain held: a `LiveSet` folded over the log from genesis.
async fn fold_live_set(store: &LocalObjectStore, history: u64) -> usize {
    let keys = LogKeys::new(A).unwrap();
    let mut set = LiveSet::default();
    for seq in 0..=history {
        let bytes = store.get(&keys.entry(seq)).await.unwrap().unwrap();
        let entry = LogEntry::parse_bytes(&bytes, A).unwrap();
        set.apply(&entry, &nanosiem_lake_worker::parts::sha256_hex(&bytes)).unwrap();
    }
    set.parts().count()
}

fn finding(id: &str, time_us: i64) -> (serde_json::Value, serde_json::Value) {
    let compact = serde_json::json!({
        "id":id, "timestamp_us":time_us, "entity":"alice@example.com",
        "stamped_entity_type":"email", "risk_score":40, "rule_id":"rule-1",
        "rule_name":"fixture", "severity":"medium", "origin_source_types":["auth"], "mitre_tactics":[]
    });
    let event = serde_json::json!({
        "class_uid":2004, "time":time_us / 1000,
        "metadata":{"uid":id,"tenant_uid":A,"log_source":"detections"},
        "unmapped":{"signal_type":"alert","alert_id":format!("alert-{id}")}
    });
    (compact, event)
}

async fn insert(admin: &sqlx::PgPool, id: &str, time_us: i64) -> SourceRef {
    let (compact, event) = finding(id, time_us);
    sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, \
        compact_finding, ocsf_event) VALUES ($1,$2,$3,$4,$5)")
        .bind(uuid::Uuid::parse_str(A).unwrap()).bind(A).bind(id)
        .bind(&compact).bind(&event).execute(admin).await.unwrap();
    FindingReceipt::new(A, id, &compact, &event).unwrap().source().unwrap()
}

/// Ground truth from genesis, no floors: receipt key → seqs of the `Add`s
/// that consumed it.
async fn consumptions(store: &LocalObjectStore) -> BTreeMap<String, Vec<u64>> {
    let keys = LogKeys::new(A).unwrap();
    let mut seqs: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for seq in 0.. {
        let Some(bytes) = store.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, A).unwrap().op {
            for source in consumed {
                seqs.entry(source.key).or_default().push(seq);
            }
        }
    }
    seqs
}

async fn setup(admin_url: &str) -> (sqlx::PgPool, sqlx::PgPool, sqlx::postgres::PgConnectOptions) {
    let server = PgPoolOptions::new().max_connections(1).connect(admin_url).await.unwrap();
    sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server).await.unwrap();
    sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE ROLE {ROLE} LOGIN")).execute(&server).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {DB}")).execute(&server).await.unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(admin_url).unwrap().database(DB);
    let admin = PgPoolOptions::new().max_connections(2).connect_with(options.clone()).await.unwrap();
    for sql in [
        "CREATE SCHEMA nano_shared".to_owned(),
        "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, published_at timestamptz, PRIMARY KEY (security_tenant_id, tenant_id, finding_id))".to_owned(),
        format!("CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE session_user WHEN '{ROLE}' THEN '{A}'::uuid END $$"),
        format!("CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user = '{ROLE}' THEN 'finding_drain' END $$"),
        format!("GRANT USAGE ON SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA nano_shared TO {ROLE}"),
        format!("GRANT SELECT, UPDATE, DELETE ON detection_finding_lake_outbox TO {ROLE}"),
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY".to_owned(),
        "CREATE POLICY drain_select ON detection_finding_lake_outbox FOR SELECT USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_update ON detection_finding_lake_outbox FOR UPDATE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
        "CREATE POLICY drain_delete ON detection_finding_lake_outbox FOR DELETE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())".to_owned(),
    ] {
        sqlx::query(&sql).execute(&admin).await.unwrap();
    }
    (server, admin, options.username(ROLE))
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

#[test]
fn the_drain_stays_under_its_memory_bound_on_a_long_log_and_delivers_every_finding_once() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "bounded drain test requires a loopback disposable risktest server");
    let history = std::env::var("NAN4691_HISTORY").ok().map(|value| value.parse::<u64>().unwrap()).unwrap_or(HISTORY);
    let ingest_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let drain_rt = drain_runtime();
    let (server, admin, drain_options) = ingest_rt.block_on(setup(&admin_url));
    let drain = drain_rt.block_on(PgPoolOptions::new().max_connections(1).connect_with(drain_options)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let store = leak(RollStore {
        inner: LocalObjectStore::new(dir.path().join("store")).unwrap(),
        entry_gets: AtomicUsize::new(0),
        cut_before: AtomicBool::new(false),
        cut_after: AtomicBool::new(false),
    });
    let signer = leak(LocalPartSigner::new("lab-drain-bounded", SigningKey::from_bytes(&[91; 32])).unwrap());
    let trusted = signer.trusted();
    let queue = leak(SpoolQueue::new(dir.path().join("spool"), A).unwrap());
    let now_ms = chrono::Utc::now().timestamp_millis();
    let time_us = (now_ms - 3_600_000) * 1_000;
    ingest_rt.block_on(write_history(&store.inner, history, now_ms));

    // The bound discriminates: the old view of this log does not fit in it.
    let (live, fold_peak) = measured(&drain_rt, fold_live_set(&store.inner, history));
    assert_eq!(live, 1);
    assert!(fold_peak > DRAIN_PEAK_BOUND, "a LiveSet fold of {history} entries peaked at {fold_peak} bytes");
    eprintln!("NAN-4691 LiveSet fold of {history} entries: peak {} MiB", fold_peak >> 20);

    let mut all = Vec::new();
    let mut generation = 0;
    let mut pass_no = 0;
    let drain_reads: &'static NoCheckpoints = leak(NoCheckpoints(store));
    let last_gets = std::cell::Cell::new(0_usize);
    let mut pass = |ingest: &IngestRole, store: &'static RollStore| {
        pass_no += 1;
        let work = dir.path().join(format!("w{pass_no}"));
        let (result, peak) = measured(&drain_rt, drain_pass(&drain, drain_reads, signer, &trusted, A, 1, ingest, &work,
            chrono::Utc::now().timestamp_millis()));
        last_gets.set(store.take());
        eprintln!("NAN-4691 pass {pass_no}: peak {} KiB, {} entry GETs, ok={}", peak >> 10, last_gets.get(), result.is_ok());
        assert!(peak < DRAIN_PEAK_BOUND, "pass {pass_no}: drain peaked at {peak} bytes on a {history}-entry log");
        result
    };

    // Round 0: an ordinary pass.
    let ids = (0..3).map(|i| format!("r0-f{i}")).collect::<Vec<_>>();
    for (i, id) in ids.iter().enumerate() {
        all.push(ingest_rt.block_on(insert(&admin, id, time_us + i as i64)));
    }
    generation += 1;
    let ingest = ingest_rt.block_on(start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")));
    store.take();
    let done = pass(&ingest, store).expect("an ordinary pass delivers");
    assert_eq!((done.seen, done.preexisting_receipts, done.published, done.committed), (3, 0, 3, 3), "{done:?}");
    assert_eq!(ingest.submits.load(Ordering::SeqCst), 1);
    drop(ingest);

    // Round 1: SIGKILL after the Add landed (acknowledgement lost). No floor
    // names these receipts: the proof after the restart starts at genesis.
    let ids = (0..3).map(|i| format!("r1-f{i}")).collect::<Vec<_>>();
    for (i, id) in ids.iter().enumerate() {
        all.push(ingest_rt.block_on(insert(&admin, id, time_us + 10 + i as i64)));
    }
    generation += 1;
    let ingest = ingest_rt.block_on(start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")));
    store.cut_after.store(true, Ordering::SeqCst);
    assert!(pass(&ingest, store).is_err(), "the kill cut the pass");
    assert!(!store.cut_after.load(Ordering::SeqCst));
    drop(ingest);
    // The floor the commit writes is best effort (a failed PUT is only
    // logged): without it, the proof after the restart starts at genesis.
    let floors = ingest_rt.block_on(store.inner.list(&floor_prefix(A).unwrap())).unwrap();
    assert!(!floors.is_empty(), "the commit wrote a floor");
    for key in floors {
        ingest_rt.block_on(store.inner.delete(&key)).unwrap();
    }
    generation += 1;
    let ingest = ingest_rt.block_on(start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")));
    store.take();
    let done = pass(&ingest, store).expect("the proof from genesis acknowledges the landed Add");
    assert!(last_gets.get() as u64 >= history, "the proof read the log from genesis: {} entry GETs", last_gets.get());
    assert_eq!((done.seen, done.preexisting_receipts, done.replay_checked, done.replayed, done.published),
        (3, 3, 3, 3, 0), "{done:?}");
    assert_eq!(ingest.submits.load(Ordering::SeqCst), 0, "no second append");
    drop(ingest);

    // Round 2: SIGKILL before the Add landed, twice: the second kill lands
    // after its genesis proof wrote a floor. The pass after it resumes from
    // that floor (no full replay loop) and delivers.
    let ids = (0..3).map(|i| format!("r2-f{i}")).collect::<Vec<_>>();
    for (i, id) in ids.iter().enumerate() {
        all.push(ingest_rt.block_on(insert(&admin, id, time_us + 20 + i as i64)));
    }
    for _ in 0..2 {
        generation += 1;
        let ingest = ingest_rt.block_on(start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")));
        store.cut_before.store(true, Ordering::SeqCst);
        assert!(pass(&ingest, store).is_err(), "the kill cut the pass");
        assert!(!store.cut_before.load(Ordering::SeqCst));
        drop(ingest);
    }
    generation += 1;
    let ingest = ingest_rt.block_on(start_ingest(dir.path(), store, queue, signer, &format!("ingest-{generation}")));
    store.take();
    pass_no += 1;
    let work = dir.path().join(format!("w{pass_no}"));
    let (result, peak) = measured(&drain_rt, drain_pass(&drain, drain_reads, signer, &trusted, A, 1, &ingest, &work,
        chrono::Utc::now().timestamp_millis()));
    let gets = store.take();
    eprintln!("NAN-4691 pass {pass_no}: peak {} KiB, {gets} entry GETs", peak >> 10);
    let done = result.expect("the pass after the kills delivers");
    assert!(peak < DRAIN_PEAK_BOUND, "pass {pass_no}: drain peaked at {peak} bytes");
    // One catch-up of the drain's view from genesis, plus the proof from its
    // floor; a second genesis scan would double it.
    assert!(gets <= history as usize + 4 * 32 + PROOF_READ_BOUND,
        "the proof resumed from its floor: {gets} entry GETs on a {history}-entry log");
    assert_eq!((done.seen, done.preexisting_receipts, done.replay_checked, done.replayed, done.published),
        (3, 3, 3, 0, 3), "{done:?}");
    assert_eq!(ingest.submits.load(Ordering::SeqCst), 1);
    drop(ingest);

    // Exactly once, from genesis: every queued finding acknowledged with the
    // one Add that consumed its receipt, and no Add consumed anything else.
    let acked: Vec<(String, Option<String>)> = ingest_rt.block_on(sqlx::query_as(
        "SELECT finding_id, event_snapshot_id FROM detection_finding_lake_outbox ORDER BY finding_id")
        .fetch_all(&admin)).unwrap();
    assert_eq!(acked.len(), 9);
    let consumed = ingest_rt.block_on(consumptions(&store.inner));
    let receipts = consumed.iter().filter(|(key, _)| !key.starts_with("bronze/h")).collect::<Vec<_>>();
    assert_eq!(receipts.len(), all.len(), "only the queued findings were consumed: {receipts:?}");
    let keys = LogKeys::new(A).unwrap();
    for ((id, head), source) in acked.iter().zip(all.iter()) {
        let seqs = consumed.get(&source.key).cloned().unwrap_or_default();
        assert_eq!(seqs.len(), 1, "{id} consumed at {seqs:?}");
        let bytes = ingest_rt.block_on(store.inner.get(&keys.entry(seqs[0]))).unwrap().unwrap();
        let sha = nanosiem_lake_worker::parts::sha256_hex(&bytes);
        assert_eq!(head.as_deref(), Some(format!("parts:{}:{sha}", seqs[0]).as_str()), "{id}");
    }

    drop(drain);
    drop(admin);
    ingest_rt.block_on(sqlx::query(&format!("DROP DATABASE IF EXISTS {DB} WITH (FORCE)")).execute(&server)).unwrap();
}
