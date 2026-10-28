// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4472: costs and convergence through the production prevalence open path.
use super::*;
use slatedb::object_store::{self, path::Path as ObjectPath};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

const TENANT: &str = "00000000-0000-4000-8000-000000004472";
const OTHER: &str = "00000000-0000-4000-8000-000000004473";

/// Emulate cold R2 RTT, count charged bytes, and hold reads to prove that
/// background work yields. All writes/opens still use production code.
#[derive(Debug, Default)]
pub(crate) struct CostStore {
    pub(crate) inner: InMemory,
    pub(crate) delay_ms: AtomicU64,
    pub(crate) bytes: AtomicU64,
    pub(crate) reads: AtomicU64,
    pub(crate) hold: AtomicBool,
    pub(crate) fail: AtomicBool,
    path_gets: [AtomicU64; 5],
    path_heads: [AtomicU64; 5],
    pub(crate) restamp_delay_ms: AtomicU64,
    pub(crate) restamp_delayed: AtomicBool,
    pub(crate) restamp_delays: AtomicU64,
}
impl CostStore {
    pub(crate) fn path_ops(&self) -> Vec<(u64, u64)> {
        super::super::prevalence_io::ReadPath::ALL
            .into_iter()
            .map(|p| {
                (
                    self.path_gets[p as usize].load(Relaxed),
                    self.path_heads[p as usize].load(Relaxed),
                )
            })
            .collect()
    }
}
impl std::fmt::Display for CostStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CostStore")
    }
}
#[async_trait::async_trait]
impl ObjectStore for CostStore {
    async fn put_opts(
        &self,
        p: &ObjectPath,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner.put_opts(p, b, o).await
    }
    async fn put_multipart_opts(
        &self,
        p: &ObjectPath,
        o: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(p, o).await
    }
    async fn get_opts(
        &self,
        p: &ObjectPath,
        o: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        let head = o.head;
        let path = super::super::prevalence_io::current_path() as usize;
        (if head {
            &self.path_heads[path]
        } else {
            &self.path_gets[path]
        })
        .fetch_add(1, Relaxed);
        let mut result = self.inner.get_opts(p, o).await?;
        if head {
            // Match remote HEAD: metadata without a body. InMemory itself
            // ignores this option and would silently warm the entire SST.
            result.payload = object_store::GetResultPayload::Stream(stream::empty().boxed());
        }
        if p.as_ref().contains("compacted/") {
            if matches!(
                super::super::prevalence_io::current_path(),
                super::super::prevalence_io::ReadPath::Restamp
            ) {
                let delay = self.restamp_delay_ms.swap(0, Relaxed);
                if delay > 0 {
                    self.restamp_delayed.store(true, Relaxed);
                    self.restamp_delays.fetch_add(1, Relaxed);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    self.restamp_delayed.store(false, Relaxed);
                }
            }
            if !head {
                self.reads.fetch_add(1, Relaxed);
                self.bytes
                    .fetch_add(result.range.end - result.range.start, Relaxed);
            }
            while self.hold.load(Relaxed) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if self.fail.load(Relaxed) {
                return Err(object_store::Error::Generic {
                    store: "test",
                    source: "injected read failure".into(),
                });
            }
            tokio::time::sleep(Duration::from_millis(self.delay_ms.load(Relaxed))).await;
        }
        Ok(result)
    }
    fn delete_stream(
        &self,
        p: futures::stream::BoxStream<'static, object_store::Result<ObjectPath>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<ObjectPath>> {
        self.inner.delete_stream(p)
    }
    fn list(
        &self,
        p: Option<&ObjectPath>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.inner.list(p)
    }
    async fn list_with_delimiter(
        &self,
        p: Option<&ObjectPath>,
    ) -> object_store::Result<object_store::ListResult> {
        self.inner.list_with_delimiter(p).await
    }
    async fn copy_opts(
        &self,
        f: &ObjectPath,
        t: &ObjectPath,
        o: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(f, t, o).await
    }
}

fn artifact(i: usize) -> String {
    crate::parts::sha256_hex(&i.to_le_bytes())
}

async fn seed(work: &Path, store: Arc<CostStore>, keys: usize) {
    let mut state = IngestPrevalence::open_with_reads(TENANT, work, None, Some(store))
        .await
        .unwrap();
    state.initialize_at(0, &"0".repeat(64)).await.unwrap();
    let mark = 10 * DAY_US;
    // Write the actual encoded window states in bounded WAL batches.
    for first in (0..keys).step_by(8_192) {
        let mut writes = WriteBatch::new();
        for i in first..(first + 8_192).min(keys) {
            let row = WindowState {
                first_seen: mark,
                last_seen: mark,
                days: vec![(10, 4)],
                hosts: (0..4).map(|h| ((i * 4 + h) as u64, 10)).collect(),
            };
            writes.put(key("hash", &artifact(i)), encode(&row));
            let ip = format!("8.{}.{}.{}", i / 65_536, i / 256 % 256, i % 256);
            writes.put(key("ip", &ip), encode(&row));
        }
        writes.put(WATERMARK_KEY, mark.to_le_bytes());
        state.commit(writes, true).await.unwrap();
    }
    state.flush_memtable().await.unwrap();
    state.close().await.unwrap();
}

#[tokio::test]
async fn cold_ingest_reads_fit_the_wait_beside_a_restamp() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), 32_768).await;
    // Cold constructor, including the tenant/schema guard and disk cache.
    let state = IngestPrevalence::open_with_reads(
        TENANT,
        &temp.path().join("cold"),
        None,
        Some(store.clone()),
    )
    .await
    .unwrap();
    store.delay_ms.store(100, Relaxed); // measured cold R2 RTT
    let background = tokio::spawn(
        state
            .lookup()
            .observe_restamp((0..4_096).map(artifact).collect(), true),
    );
    // The small fixture can fit in RAM; charge every foreground key the
    // measured 100 ms cold cost as well, so the old 64-lane production
    // path really overruns 5 s (3500 / 64 * 100 ms), even with hot blocks.
    let mut foreground = state.lookup();
    foreground.read_delay = Some(Duration::from_millis(100));
    let began = std::time::Instant::now();
    let observed = tokio::time::timeout(
        super::super::ingest::PREVALENCE_INGEST_WAIT,
        foreground.observe((0..3_500).map(|i| artifact(i * 9)).collect()),
    )
    .await
    .expect("a large-tenant-shaped cold batch must fit the production ingest wait")
    .unwrap();
    assert_eq!(observed.rows.len(), 3_500);
    assert!(observed.scalars().values().all(|n| *n == 4));
    let ingest_elapsed = began.elapsed();
    let (scalars, complete) = background.await.unwrap().unwrap();
    assert!(complete);
    assert_eq!(scalars.len(), 4_096);
    eprintln!(
        "cold 3500-key ingest beside restamp: {ingest_elapsed:?}; SST bytes {}, GETs {}",
        store.bytes.load(Relaxed),
        store.reads.load(Relaxed)
    );
    state.close().await.unwrap();
}

#[tokio::test]
async fn routine_budget_keeps_progress_and_sealed_work_resumes_past_ten_seconds() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), 256_000).await;
    let state = IngestPrevalence::open_with_reads(
        TENANT,
        &temp.path().join("cold"),
        None,
        Some(store.clone()),
    )
    .await
    .unwrap();
    // Charge lookup latency even when 4 MiB prefetch warmed the fixture.
    // This component proves budget semantics independently of cache shape;
    // the pipeline fixture separately delays actual production object I/O.
    let artifacts = (0..1_024).map(artifact).collect::<BTreeSet<_>>();
    state
        .lookup()
        .observe(artifacts.iter().take(64).cloned().collect())
        .await
        .unwrap();
    let mut routine_lookup = state.lookup();
    routine_lookup.read_delay = Some(Duration::from_millis(400));
    let mut sealed_lookup = state.lookup();
    sealed_lookup.read_delay = Some(Duration::from_millis(400));
    let routine = tokio::spawn(routine_lookup.observe_restamp(artifacts.clone(), false));
    let sealed = tokio::spawn(sealed_lookup.observe_restamp(artifacts, true));
    tokio::time::sleep(
        super::super::restamp::RESTAMP_MERGE_LOOKUP_TIMEOUT + Duration::from_millis(50),
    )
    .await;
    let (partial, complete) = routine.await.unwrap().unwrap();
    assert!(!complete);
    assert!(partial.len() >= 64, "completed lookups survive the budget");
    assert!(
        !sealed.is_finished(),
        "a budget yield does not cancel the sealed hour"
    );
    let (all, complete) = tokio::time::timeout(Duration::from_secs(15), sealed)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(complete);
    assert_eq!(all.len(), 1_024);
    assert!(partial.iter().all(|(k, v)| all.get(k) == Some(v)));
    state.close().await.unwrap();
}

#[tokio::test]
async fn production_open_rejects_another_tenants_state_for_both_lookup_paths() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), 16).await;
    let error =
        IngestPrevalence::open_with_reads(OTHER, &temp.path().join("other"), None, Some(store))
            .await
            .err()
            .unwrap();
    assert!(error.to_string().contains("tenant or schema differs"));
}

#[tokio::test]
async fn failed_restamp_reads_do_not_become_absent_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), 256_000).await;
    let state = IngestPrevalence::open_with_reads(
        TENANT,
        &temp.path().join("cold"),
        None,
        Some(store.clone()),
    )
    .await
    .unwrap();
    store.fail.store(true, Relaxed);
    assert!(state
        .lookup()
        .observe_restamp((0..32_768).map(artifact).collect(), true)
        .await
        .is_err());
    store.fail.store(false, Relaxed);
    state.close().await.unwrap();
}

/// Component check of three actual 1M-row Arrow rewrites, followed by an
/// explicit analytical ETA. Production ingestion/planning/owed convergence
/// is proved separately in prevalence_pipeline_tests, without manual clears.
#[tokio::test]
async fn b12_three_million_row_arrow_component_and_analytical_drain_cost() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.read().await;
    use super::super::restamp::{restamp_batch, RestampMap};
    use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray, UInt16Array};
    use arrow_schema::{DataType, Field, Schema};
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), 144_000).await;
    let state =
        IngestPrevalence::open_with_reads(TENANT, &temp.path().join("cold"), None, Some(store))
            .await
            .unwrap();
    let mut fields = vec![Field::new(
        "dst_endpoint",
        DataType::Struct(vec![Field::new("ip", DataType::Utf8, true)].into()),
        true,
    )];
    fields.extend(
        stamp_columns()
            .iter()
            .map(|name| Field::new(*name, DataType::UInt16, true)),
    );
    let schema = Arc::new(Schema::new(fields));
    // 144k artifacts for 1M rows, measured in the supplied large-tenant log.
    let distinct = 144_000;
    let artifacts = (0..distinct)
        .map(|i| format!("8.{}.{}.{}", i / 65_536, i / 256 % 256, i % 256))
        .collect::<BTreeSet<_>>();
    for _ in 0..3 {
        let (scalars, complete) = state
            .lookup()
            .observe_restamp(artifacts.clone(), true)
            .await
            .unwrap();
        assert!(complete);
        assert_eq!(scalars.len(), distinct);
        assert!(
            scalars.values().all(|n| *n == 4),
            "the loaded production state is actually read"
        );
        let map = RestampMap::new(scalars);
        for first in (0..1_000_000).step_by(8_192) {
            let len = 8_192.min(1_000_000 - first);
            let ip = StringArray::from(
                (first..first + len)
                    .map(|i| {
                        let k = i % distinct;
                        format!("8.{}.{}.{}", k / 65_536, k / 256 % 256, k % 256)
                    })
                    .collect::<Vec<_>>(),
            );
            let dst = StructArray::from(vec![(
                Arc::new(Field::new("ip", DataType::Utf8, true)),
                Arc::new(ip) as ArrayRef,
            )]);
            let mut columns: Vec<ArrayRef> = vec![Arc::new(dst)];
            columns.extend((0..5).map(|_| Arc::new(UInt16Array::new_null(len)) as ArrayRef));
            let stamped =
                restamp_batch(RecordBatch::try_new(schema.clone(), columns).unwrap(), &map)
                    .unwrap();
            assert_eq!(stamped.num_rows(), len);
        }
        assert_eq!(map.restamped_rows(), 1_000_000);
    }
    // Conditional cost model, not observed throughput. Dense reads retain
    // 4 MiB parts and charge one 3 GiB state sweep; RTT assumes a pessimistic
    // one remote request/key. Preserve the large tenant's measured ~15m21s rewrite cost,
    // rounded upward to 15.5 min, and the production 30s restamp spacing.
    let cost = |lanes: usize| {
        3_072.0 / 130.0
            + (distinct as f64 / lanes as f64).ceil() * 0.1
            + 15.5 * 60.0
            + super::super::restamp::RESTAMP_SPACING_MS as f64 / 1_000.0
    };
    let nominal_hours = 70.0 * cost(RESTAMP_READS) / 3_600.0;
    assert!(nominal_hours < 24.0 && nominal_hours < 37.5);
    for lanes in [16, 32, RESTAMP_READS, 128] {
        eprintln!(
            "analytical drain: {lanes} lanes, {:.1} min/hour, {:.1} hours for 70 hours",
            cost(lanes) / 60.0,
            70.0 * cost(lanes) / 3_600.0
        );
    }
    state.close().await.unwrap();
}

/// NAN-4592: the disk cache sized from the state ([`object_cache_bytes`])
/// against the fixed 256 MiB it had, for a large-tenant-like key working set: a state
/// several times the old cache (the large tenant: ~3 GiB against 256 MiB) and batches of
/// distinct random artifacts (the large tenant: ~2k point reads per flush). Same seeded
/// objects, the production open (`open_sized`, what `spawn_prevalence_open`
/// calls); only the tenant's cap differs. GETs and bytes are counted at the
/// physical store for every read path, including SST data blocks that SlateDB
/// fetches on its own tasks (charged to "maintenance").
#[tokio::test]
async fn state_sized_disk_cache_cuts_r2_gets_per_stamped_batch() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    // Scaled to a debug-build test: a ~20 MB state (5 cache parts) against
    // a one-part fixed cache, and 1,000-key batches.
    const KEYS: usize = 262_144;
    const BATCH: usize = 1_000;
    const BATCHES: usize = 6;
    const WARM: usize = 2;
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(CostStore::default());
    seed(&temp.path().join("seed"), store.clone(), KEYS).await;
    let state_bytes: u64 = store
        .inner
        .list(None)
        .filter_map(|meta| async move { meta.ok() })
        .filter(|meta| std::future::ready(meta.location.as_ref().contains("compacted/")))
        .map(|meta| meta.size)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .sum();
    let part = OBJECT_CACHE_PART_BYTES as u64;
    // As on the large tenant (the fixed 256 MiB against a ~3 GiB state), the fixed cache
    // holds a small share of the state: here one 4 MiB part of ~5.
    let old_cap = part;
    assert!(state_bytes >= 4 * part, "the state spans several 4 MiB parts: {state_bytes}");
    // Distinct keys in every batch (the value cache never answers), spread
    // uniformly over the state.
    let stride = KEYS / (BATCH * BATCHES);
    let batch = |b: usize| (0..BATCH).map(|j| artifact((j * BATCHES + b) * stride)).collect::<BTreeSet<_>>();
    let mut measured = Vec::new();
    for (name, cap) in [("fixed", old_cap), ("sized", u64::MAX)] {
        assert_eq!(
            object_cache_bytes(Some(state_bytes), cap),
            if cap == u64::MAX { (2 * state_bytes).max(OBJECT_CACHE_FLOOR_BYTES) } else { old_cap }
        );
        let state = IngestPrevalence::open_sized(TENANT, &temp.path().join(name), None, Some(store.clone()), cap,
            LocalStateSizing::FLOOR)
            .await
            .unwrap();
        // The open measured this tenant's own SSTs (one LIST) and sized the
        // cache from them within the cap.
        assert_eq!(
            state.object_cache_sizing(),
            (Some(state_bytes), object_cache_bytes(Some(state_bytes), cap)),
            "{name}: the cache is sized from the measured state"
        );
        let (mut gets, mut bytes) = (0_u64, 0_u64);
        for b in 0..BATCHES {
            let (g0, b0) = (store.reads.load(Relaxed), store.bytes.load(Relaxed));
            let observed = state.lookup().observe(batch(b)).await.unwrap();
            assert_eq!(observed.rows.len(), BATCH);
            assert!(observed.scalars().values().all(|n| *n == 4), "{name}: every artifact reads its seeded count");
            if b >= WARM {
                gets += store.reads.load(Relaxed) - g0;
                bytes += store.bytes.load(Relaxed) - b0;
            }
        }
        let per = (BATCHES - WARM) as u64;
        eprintln!(
            "{name} cache (cap {cap}, state {state_bytes} B): {} GETs, {} B per stamped batch after warm-up; per path {}",
            gets / per,
            bytes / per,
            serde_json::to_string(&state.read_stats()).unwrap()
        );
        measured.push((gets / per, bytes / per));
        state.close().await.unwrap();
    }
    let ((old_gets, old_bytes), (new_gets, new_bytes)) = (measured[0], measured[1]);
    assert!(old_gets >= 10, "the fixed cache misses on the large tenant's working set: {old_gets} GETs per batch");
    assert!(
        new_gets * 10 <= old_gets && new_bytes * 10 <= old_bytes,
        "a state-sized cache cuts GETs and bytes per stamped batch at least 10x: \
         {new_gets} GETs / {new_bytes} B vs {old_gets} GETs / {old_bytes} B"
    );
}

/// NAN-4592: a state on its own disk keeps the floor; a remote state's cache
/// follows its measured SSTs within the tenant cap.
#[test]
fn disk_cache_follows_the_measured_state_within_the_cap() {
    const MIB: u64 = 1024 * 1024;
    let floor = OBJECT_CACHE_FLOOR_BYTES;
    assert_eq!(object_cache_bytes(None, 8 * 1024 * MIB), floor, "unmeasured: the old fixed cache");
    assert_eq!(object_cache_bytes(Some(10 * MIB), 8 * 1024 * MIB), floor, "a small state keeps the floor");
    assert_eq!(object_cache_bytes(Some(3 * 1024 * MIB), 8 * 1024 * MIB), 6 * 1024 * MIB, "the large tenant: twice its state");
    assert_eq!(object_cache_bytes(Some(3 * 1024 * MIB), 4 * 1024 * MIB), 4 * 1024 * MIB, "never past the cap");
    assert_eq!(object_cache_bytes(Some(u64::MAX), u64::MAX), u64::MAX);
}
