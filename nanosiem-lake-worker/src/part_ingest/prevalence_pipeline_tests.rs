// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4472: drive publication, apply, scheduling and owed clearance, not a
//! parallel implementation of the conditions being proved.
use super::super::discovery::{SourceNotice, SpoolQueue};
use super::super::prevalence::steady_tests::CostStore;
use super::*;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use arrow_json::reader::{infer_json_schema_from_seekable, ReaderBuilder};
use parquet::arrow::ArrowWriter;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

const TENANT: &str = "00000000-0000-4000-8000-000000004472";
const START: i64 = 1_790_294_400_000;
const HOUR: i64 = 3_600_000;
const ROWS: usize = 1_000; // 1:1000 rows; a physical hour represents 1M rows.
const HOURS: i64 = 70;
const KEYS: usize = 144; // 144k artifacts/hour at the same row scale.

struct Parts {
    inner: LocalObjectStore,
    delay_ms: AtomicU64,
    hour_data_puts: AtomicU64,
}
#[async_trait::async_trait]
impl ObjectStore for Parts {
    async fn get(&self, k: &str) -> Result<Option<Vec<u8>>> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms.load(Relaxed))).await;
        self.inner.get(k).await
    }
    async fn get_range(&self, k: &str, r: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        self.inner.get_range(k, r).await
    }
    async fn object_size(&self, k: &str) -> Result<Option<u64>> {
        self.inner.object_size(k).await
    }
    async fn put_if_absent(&self, k: &str, b: &[u8]) -> Result<bool> {
        tokio::time::sleep(Duration::from_millis(self.delay_ms.load(Relaxed))).await;
        if k.contains("/h/") && k.ends_with(".parquet") && k.contains("data-") {
            self.hour_data_puts.fetch_add(1, Relaxed);
        }
        self.inner.put_if_absent(k, b).await
    }
    async fn put(&self, k: &str, b: &[u8]) -> Result<()> {
        self.inner.put(k, b).await
    }
    async fn delete(&self, k: &str) -> Result<()> {
        self.inner.delete(k).await
    }
    async fn list(&self, k: &str) -> Result<Vec<String>> {
        self.inner.list(k).await
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    store: &'static Parts,
    signer: &'static LocalPartSigner,
    queue: SpoolQueue,
    state: Arc<CostStore>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let store = Box::leak(Box::new(Parts {
            inner: LocalObjectStore::new(root.join("objects")).unwrap(),
            delay_ms: AtomicU64::new(0),
            hour_data_puts: AtomicU64::new(0),
        }));
        let signer = Box::leak(Box::new(
            LocalPartSigner::new(
                "pipeline-4472",
                ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
            )
            .unwrap(),
        ));
        let queue = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
        Self {
            _temp: temp,
            root,
            store,
            signer,
            queue,
            state: Arc::new(CostStore::default()),
        }
    }
    fn config(&self, work: &str, enabled: bool, main: bool) -> IngestConfig {
        let mut cfg = IngestConfig::new(TENANT, self.root.join(work));
        cfg.prevalence_enabled = enabled;
        cfg.prevalence_read_store = Some(self.state.clone());
        cfg.prevalence_main_read_policy = main;
        cfg.background_merges = true;
        cfg.flush_interval_override_ms = Some(35_000);
        cfg.prevalence_ingest_wait = Duration::from_millis(150);
        cfg.prevalence_rebuild_budget_ms = 20;
        cfg.prevalence_op_timeout = Duration::from_secs(30);
        cfg
    }
    async fn open(&self, work: &str, enabled: bool, main: bool, now: i64) -> Ingestor<'_> {
        let mut i = Ingestor::open(
            self.config(work, enabled, main),
            self.store,
            self.store,
            &self.queue,
            self.signer,
            self.signer.trusted(),
            BronzeIngestEnricher::disabled(),
            &seed_schema(),
            now,
        )
        .await
        .unwrap();
        // These are the exact production background publication/signing seams.
        i.set_background_store(self.store);
        i.set_background_signer(self.signer);
        i
    }
    fn source(&self, id: usize, now: i64, rows: usize, historical: bool, lag: i64) {
        let mut ndjson = Vec::new();
        for r in 0..rows {
            let k = if historical {
                500 + r % KEYS
            } else {
                100_000 + (id * 10 + r) % if id < 20_000 { KEYS } else { 3_500 }
            };
            let digest = crate::parts::sha256_hex(&(k as u64).to_le_bytes());
            // Recent keys sort beyond the historical cohort. Their priming
            // cannot prefetch historical middle parts on a bloom false hit.
            let hash = if historical {
                digest
            } else {
                format!("ffffffffffffffff{}", &digest[..48])
            };
            let time =
                chrono::DateTime::from_timestamp_millis(now - lag - 2_000 + (r % 1000) as i64)
                    .unwrap()
                    .to_rfc3339();
            let value = serde_json::json!({"time":time,"class_uid":4010,"category_uid":4,"activity_id":1,"type_uid":401001,"severity_id":1,
                "metadata":{"uid":format!("p-{id}-{r}"),"tenant_uid":TENANT,"version":"1.9.0","log_source":"fixture","product":{"name":"fixture","vendor_name":"nano"}},
                "actor":{"user":{"name":"fixture"}},"src_endpoint":{"hostname":format!("host-{}",id%70)},
                "dst_endpoint":{"ip":"8.8.8.8"},"file":{"name":"fixture.exe","type_id":1,"hashes":[{"algorithm":"SHA-256","algorithm_id":3,"value":hash}]},
                "raw_data":"fixture","raw_data_size":7,"message":"file observed"});
            if r == 0 {
                let mut contract = value.clone();
                contract["time"] = serde_json::json!(now - lag - 2_000);
                let checked = nanosiem_core::parsers::validate_ocsf_event(&contract);
                assert!(
                    checked.valid,
                    "invalid pipeline source: {:?}",
                    checked.errors
                );
            }
            serde_json::to_writer(&mut ndjson, &value).unwrap();
            ndjson.push(b'\n');
        }
        let (schema, _) =
            infer_json_schema_from_seekable(&mut std::io::Cursor::new(&ndjson), None).unwrap();
        let reader = ReaderBuilder::new(Arc::new(schema.clone()))
            .build(std::io::Cursor::new(ndjson))
            .unwrap();
        let key = format!("bronze/p-{id}.parquet");
        let path = self.root.join("objects").join(&key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut writer =
            ArrowWriter::try_new(std::fs::File::create(path).unwrap(), Arc::new(schema), None)
                .unwrap();
        for batch in reader {
            writer.write(&batch.unwrap()).unwrap();
        }
        writer.close().unwrap();
        self.queue
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(),
                key,
                version: "1".into(),
                bytes: 0,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: now - lag,
            })
            .unwrap();
    }
}
async fn quiet(i: &mut Ingestor<'_>, now: &mut i64, sealed: bool) {
    let end = Instant::now() + Duration::from_secs(40);
    loop {
        i.tick(*now).await.unwrap();
        *now += 1_000;
        if i.merge_in_flight.is_empty()
            && (!sealed || i.log.live().parts().all(|p| p.level == Level::Hour))
        {
            return;
        }
        assert!(
            Instant::now() < end,
            "production background planner did not settle"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn foreground_stats(i: &Ingestor<'_>) -> (u64, u64, u64) {
    let stats = i.prevalence.as_ref().unwrap().read_stats();
    stats
        .iter()
        .filter(|s| matches!(s.path, "stamp" | "apply"))
        .fold((0, 0, 0), |(g, b, h), s| {
            (g + s.gets + s.heads, b + s.bytes, h + s.point_cache_hits)
        })
}

fn all_ops(i: &Ingestor<'_>) -> u64 {
    i.prevalence
        .as_ref()
        .unwrap()
        .read_stats()
        .iter()
        .map(|s| s.gets + s.heads)
        .sum()
}
#[tokio::test]
async fn b12_production_pipeline_drains_seventy_sealed_hours_while_ingesting_and_committing_l0() {
    // The 5s admission+flush ceiling is measured with a CPU budget, not beside
    // another test's 3M-row rewrite/large cold-state experiment. Keep the bound.
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    let f = Fixture::new();
    let mut now = START;
    let mut i = f.open("old", false, false, now).await;
    for hour in 0..HOURS {
        now = START + hour * HOUR + 120_000;
        f.source(hour as usize, now, ROWS, true, 80_000);
        let admitted = i.tick(now).await.unwrap();
        assert_eq!(
            admitted.admitted_rows, ROWS as u64,
            "historical source must pass real admission"
        );
        i.flush_now(now).await.unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    now = START + (HOURS + 2) * HOUR;
    quiet(&mut i, &mut now, true).await;
    assert_eq!(i.log.live().parts().count(), HOURS as usize);
    drop(i);
    let mut i = f.open("rebuild", true, false, now).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    while i.prevalence_status() != "stamping" {
        i.tick(now).await.unwrap();
        now += 500;
        assert!(
            Instant::now() < deadline,
            "replay never reached head: {}",
            i.prevalence_status()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // Unrelated historical keys create a state larger than the data block
    // cache; reopening makes the object cache genuinely cold too. The real
    // signed source Adds above remain the sole authority for the owed hours.
    i.prevalence
        .as_mut()
        .unwrap()
        .seed_io_pressure_for_test(600_000)
        .await
        .unwrap();
    i.prevalence.take().unwrap().close().await.unwrap();
    drop(i);
    let mut i = f.open("serving", true, false, now).await;
    while i.prevalence_status() != "stamping" {
        i.tick(now).await.unwrap();
        now += 500;
    }
    // Real admissions of a new cohort: apply writes through the value cache.
    // They do not read historical known hashes and prewarm the future restamp.
    f.source(10_000, now, KEYS, false, 80_000);
    i.tick(now).await.unwrap();
    i.flush_now(now).await.unwrap();
    quiet(&mut i, &mut now, false).await;
    let start = START;
    let end = START + HOURS * HOUR;
    let hours = i
        .queue_prevalence_restamp(
            super::super::reindex::CountBackfill {
                start_ms: start,
                end_ms: end - 1,
            },
            now,
        )
        .unwrap();
    assert_eq!(hours.len(), HOURS as usize);
    assert_eq!(i.prevalence_owed_hours().len(), HOURS as usize);
    f.state.restamp_delay_ms.store(12_500, Relaxed); // spans the actual 10s slice
    f.store.delay_ms.store(1, Relaxed);
    let minutes_before = i
        .log
        .live()
        .parts()
        .filter(|p| p.level == Level::Minute)
        .map(|p| p.part_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let before = foreground_stats(&i);
    let unstamped = i.health.prevalence_unstamped_batches_total;
    let mut previous = i.prevalence_owed_hours();
    let (mut arrivals, mut clears, mut natural_lag, mut overdue, mut l0_during_lookup) =
        (0, 0, false, false, false);
    let mut worst = Duration::ZERO;
    let began = Instant::now();
    let clock_start = now;
    let deadline = began + Duration::from_secs(180);
    let mut next_arrival = began;
    while !i.prevalence_owed_hours().is_empty() || arrivals < 20 {
        assert!(
            Instant::now() < deadline,
            "owed did not converge through production commits: {} remain",
            i.prevalence_owed_hours().len()
        );
        // Clock scale 1:40, including time spent doing real work. A source
        // arrives every 35 virtual seconds throughout the entire drain.
        // Keep production's 30s rewrite spacing and real 10s lookup slices.
        now = clock_start + began.elapsed().as_millis() as i64 * 40;
        if Instant::now() >= next_arrival {
            let lag = [71_910, 98_018, 85_000, 76_000][arrivals % 4];
            f.source(10_001 + arrivals, now, 10, false, lag);
            let at = Instant::now();
            i.tick(now).await.unwrap();
            natural_lag |= (70_000..=100_000).contains(&i.health.lag_ms);
            i.flush_now(now).await.unwrap();
            worst = worst.max(at.elapsed());
            assert!(
                at.elapsed() < Duration::from_millis(500),
                "admission held by background work for {:?}",
                at.elapsed()
            );
            arrivals += 1;
            next_arrival += Duration::from_millis(875);
        } else {
            i.tick(now).await.unwrap();
        }
        assert!(
            i.restamp_retry.is_empty(),
            "sealed lookups must resume without a failed-hour retry"
        );
        let delayed = f.state.restamp_delayed.load(Relaxed);
        if delayed {
            assert_eq!(
                i.health.prevalence_restamp_rewrites_total, 0,
                "a read still spanning slices cannot clear an owed hour"
            );
            assert_eq!(i.prevalence_owed_hours().len(), HOURS as usize);
            overdue |= crate::parts::levels::l0_merge_overdue_ms(
                i.log.live().parts(),
                now,
                &i.cfg.merge_policy,
            ) > 0;
            l0_during_lookup |= i.log.live().parts().any(|p| {
                p.level == Level::Minute
                    && !minutes_before.contains(&p.part_id)
                    && p.event_hour >= event_hour_of((START + (HOURS + 2) * HOUR) * 1_000)
            });
        }
        let owed = i.prevalence_owed_hours();
        assert!(
            owed.iter().all(|h| previous.contains(h)),
            "ongoing admission added an owed hour"
        );
        if owed.len() != previous.len() {
            assert!(owed.len() < previous.len());
            clears += previous.len() - owed.len();
            previous = owed;
            assert_eq!(
                i.health.prevalence_restamp_given_up_total, 0,
                "clear must be a committed restamp"
            );
            assert_eq!(
                HOURS as usize - previous.len(),
                i.health.prevalence_restamp_rewrites_total as usize
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(clears, HOURS as usize);
    assert!(
        natural_lag,
        "real pending-notice lag never reached the large tenant's range"
    );
    assert!(
        overdue && l0_during_lookup,
        "L0 must actually become overdue and commit while the restamp read spans slices"
    );
    assert_eq!(
        f.state.restamp_delays.load(Relaxed),
        1,
        "the production restamp must perform delayed object I/O"
    );
    assert_eq!(i.health.prevalence_unstamped_batches_total, unstamped);
    assert_eq!(
        i.health.prevalence_restamped_rows_total,
        HOURS as u64 * ROWS as u64
    );
    assert!(i.prevalence_owed_hours().is_empty());
    quiet(&mut i, &mut now, false).await;
    // Actual committed Adds, including every concurrent admission, reached
    // the counted state. Historical rewrites must neither add nor lose counts.
    let state = i.prevalence.as_ref().unwrap();
    let mut probe = serde_json::json!({"dst_endpoint":{"ip":"8.8.8.8"}});
    state.stamp(&mut probe).await.unwrap();
    assert_eq!(
        probe["enrichments"][0]["data"]["total_occurrences"],
        HOURS as u64 * ROWS as u64 + KEYS as u64 + arrivals as u64 * 10
    );
    let after = foreground_stats(&i);
    eprintln!("production: {} sealed hours cleared, {} real Adds, worst admission {:?}, new foreground GET/HEAD {}, bytes {}, value-cache hits {}, actual L0 during delayed restamp={}",clears,arrivals,worst,after.0-before.0,after.1-before.1,after.2-before.2,l0_during_lookup);
    // Cost gate also uses unscaled 3,500-key batches at the large tenant's 35s cadence.
    // This is separate from the row-scaled convergence workload above.
    i.cfg.prevalence_ingest_wait = Duration::from_secs(5);
    f.source(30_000, now, 3_500, false, 80_000);
    i.tick(now).await.unwrap();
    i.flush_now(now).await.unwrap();
    let full_before = all_ops(&i);
    let fake_before = f.state.path_ops();
    // NAN-4539 follow-up: the absolute 5 s wall-clock bound failed whenever
    // the farm ran the whole lib suite in parallel (and passed alone). What
    // it guards is that admission never blocks on prevalence past its wait:
    // a prevalence stall shows as a tick a full wait slower than its peers,
    // whatever the machine's load. So bound each tick against the median of
    // the 20 (same work each), plus a hang ceiling.
    // NAN-4622: a uniform stall (every tick waits the full wait) moves the
    // median with the worst tick, so the relative bound alone cannot see it.
    // The overrun counters count exactly that stall, independent of load.
    let (deferred_before, unstamped_before) = (
        i.health.prevalence_deferred_total,
        i.health.prevalence_unstamped_batches_total,
    );
    let mut elapsed = Vec::with_capacity(20);
    for n in 0..20 {
        now += 35_000;
        f.source(30_001 + n, now, 3_500, false, 80_000);
        let at = Instant::now();
        i.tick(now).await.unwrap();
        i.flush_now(now).await.unwrap();
        elapsed.push(at.elapsed());
        assert!(elapsed[n as usize] < Duration::from_secs(60), "full large-tenant admission hung: {:?}", elapsed[n as usize]);
    }
    let mut sorted = elapsed.clone();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    let worst = *sorted.last().unwrap();
    assert!(
        worst.saturating_sub(median) < i.cfg.prevalence_ingest_wait,
        "full large-tenant admission exceeded its wait: worst {worst:?} vs median {median:?} (wait {:?})",
        i.cfg.prevalence_ingest_wait
    );
    assert_eq!(
        (
            i.health.prevalence_deferred_total - deferred_before,
            i.health.prevalence_unstamped_batches_total - unstamped_before,
        ),
        (0, 0),
        "full large-tenant admission overran the prevalence wait (deferred, unstamped)"
    );
    let full_after = all_ops(&i);
    let fake_after = f.state.path_ops();
    let measured_delta = |a: &[(u64, u64)], b: &[(u64, u64)]| {
        a.iter()
            .zip(b)
            .map(|(a, b)| a.0 + a.1 - b.0 - b.1)
            .sum::<u64>()
    };
    assert_eq!(
        full_after - full_before,
        measured_delta(&fake_after, &fake_before),
        "production metrics match physical fake-store GET/HEAD"
    );
    let new_ops = measured_delta(&fake_after, &fake_before) as f64 / 20.0;
    eprintln!(
        "per-path production I/O: {}",
        serde_json::to_string(&i.prevalence.as_ref().unwrap().read_stats()).unwrap()
    );
    quiet(&mut i, &mut now, false).await;
    i.prevalence.take().unwrap().close().await.unwrap();
    drop(i);
    // Compare main's 4 MiB/32 MiB block-cache policy on the SAME tenant,
    // seeded objects and production constructor, with no value cache.
    let mut main = f.open("main-cost", true, true, now).await;
    main.cfg.prevalence_ingest_wait = Duration::from_secs(5);
    while main.prevalence_status() != "stamping" {
        main.tick(now).await.unwrap();
        now += 500;
    }
    f.source(20_000, now, 3_500, false, 80_000);
    main.tick(now).await.unwrap();
    main.flush_now(now).await.unwrap();
    let baseline = all_ops(&main);
    let fake_baseline = f.state.path_ops();
    for n in 0..20 {
        now += 35_000;
        f.source(20_001 + n, now, 3_500, false, 80_000);
        main.tick(now).await.unwrap();
        main.flush_now(now).await.unwrap();
    }
    let baseline_after = all_ops(&main);
    let fake_baseline_after = f.state.path_ops();
    assert_eq!(
        baseline_after - baseline,
        measured_delta(&fake_baseline_after, &fake_baseline)
    );
    let main_ops = measured_delta(&fake_baseline_after, &fake_baseline) as f64 / 20.0;
    let extra_per_day = (new_ops - main_ops).max(0.0) * 86_400.0 / 35.0;
    assert!(
        extra_per_day <= 1_000_000.0,
        "CF hard gate: +{extra_per_day:.0} GET/HEAD per tenant/day"
    );
    eprintln!("CF steady state: new {new_ops:.3} vs main {main_ops:.3} GET/HEAD per batch; delta +{extra_per_day:.0}/tenant/day; all SST paths retain 4 MiB parts");
    quiet(&mut main, &mut now, false).await;
    main.prevalence.take().unwrap().close().await.unwrap();
}

/// NAN-4539: use the production constructor/admission/flush, including real
/// publication, signature, log and prevalence paths; only storage is local.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_stage_timings_survive_short_foreground_stages_and_are_value_free() {
    let f = Fixture::new();
    let mut i = f.open("timings-foreground", true, false, START).await;
    let heartbeat = i.diagnostics();
    assert_eq!(heartbeat.snapshot()["occupancy"]["effective_flush_depth"], 1);
    f.source(0, START, 20, false, 0);
    i.tick(START).await.unwrap();
    i.flush(START + 1, false).await.unwrap();
    let snapshot = heartbeat.snapshot();
    let flush = &snapshot["last_completed_flush"];
    assert_eq!(flush["stage"], "complete");
    assert_eq!(flush["rows"], 20);
    assert!(flush["arrow_bytes"].as_u64().unwrap() > 0);
    assert!(flush["part_file_bytes"].as_u64().unwrap() > 0);
    assert_eq!(flush["part_rows"], 20);
    let history = flush["history"].as_array().unwrap();
    for stage in ["build_parts", "publish_parts", "append_part_log", "apply_prevalence", "edge_ack"] {
        assert!(history.iter().any(|entry| entry["stage"] == stage), "{stage}: {snapshot}");
        assert!(snapshot["flush_stage_timings"][stage]["finished_total"].as_u64().unwrap() > 0);
        assert_eq!(snapshot["flush_stage_timings"][stage]["in_flight"], 0);
    }
    for operation in ["part_file_upload", "signatures", "provenance_and_cache", "part_log_append", "prevalence_apply"] {
        assert_eq!(snapshot["operation_timings"][operation]["finished_total"], 1, "{operation}");
        assert_eq!(snapshot["operation_timings"][operation]["in_flight"], 0);
    }
    assert_eq!(snapshot["flushes_in_flight"], 0);
    assert_eq!(snapshot["queue_sample"]["pending_sampled"], 1);
    assert_eq!(snapshot["queue_sample"]["fresh_pending_sampled"], 1);
    assert!(snapshot["occupancy"]["working_budget_bytes"].as_u64().unwrap() > 0);
    assert_eq!(snapshot["occupancy"]["queue_range_capacity"], 1);
    assert_eq!(snapshot["occupancy"]["working_reserved_bytes"], 0);
    assert_eq!(i.health().rows_committed_total, 20);
    assert!(f.queue.pending(10).await.unwrap().is_empty());
    for value in [TENANT, "bronze/p-0.parquet", "p-0-0", "fixture.exe", "8.8.8.8", "pipeline-4472"] {
        assert!(!snapshot.to_string().contains(value), "diagnostics leaked {value}");
    }
    i.prevalence.take().unwrap().close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_stage_timings_background_progress_is_observable_without_an_ingest_tick() {
    let f = Fixture::new();
    let mut i = f.open("timings-background", false, false, START).await;
    f.source(1, START, 20, false, 0);
    i.tick(START).await.unwrap();
    f.store.delay_ms.store(50, Relaxed);
    i.flush(START + 1, true).await.unwrap();
    let heartbeat = i.diagnostics();
    // Observe the real background task without re-entering mutable ingest.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = heartbeat.snapshot();
            if snapshot["oldest_flush_stage"] == "awaiting_part_log" { break; }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.unwrap();
    let snapshot = heartbeat.snapshot();
    assert_eq!(snapshot["oldest_flush"]["rows"], 20);
    assert_eq!(snapshot["flushes_in_flight"], 1);
    assert_eq!(snapshot["operation_timings"]["signatures"]["finished_total"], 1);
    assert_eq!(snapshot["flush_stage_timings"]["publish_parts"]["in_flight"], 0);
    assert!(snapshot["flush_stage_timings"]["publish_parts"]["elapsed_us_total"].as_u64().unwrap() >= 50_000);
    i.flush(START + 2, false).await.unwrap();
    assert_eq!(heartbeat.snapshot()["last_completed_flush"]["rows"], 20);
    assert_eq!(i.health().rows_committed_total, 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingest_stage_timings_and_notices_do_not_cross_tenant_constructors() {
    let f = Fixture::new();
    let mut a = f.open("timings-a", false, false, START).await;
    const OTHER: &str = "00000000-0000-4000-8000-000000004539";
    let queue = SpoolQueue::new(f.root.join("spool-b"), OTHER).unwrap();
    let mut cfg = IngestConfig::new(OTHER, f.root.join("timings-b"));
    cfg.prevalence_enabled = false;
    let b = Ingestor::open(cfg, f.store, f.store, &queue, f.signer, f.signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), START).await.unwrap();
    f.source(2, START, 20, false, 0);
    let foreign = f.queue.pending(1).await.unwrap().remove(0).1;
    assert!(queue.deliver(&foreign).is_err());
    a.tick(START).await.unwrap();
    a.flush(START + 1, false).await.unwrap();
    assert_eq!(a.health().rows_committed_total, 20);
    let peer = b.diagnostics().snapshot();
    assert_eq!(peer["flush_stage_timings"], serde_json::json!({}));
    assert_eq!(peer["operation_timings"], serde_json::json!({}));
    assert!(peer["last_completed_flush"].is_null());
    assert_eq!(b.health().rows_committed_total, 0);
    assert!(b.live_parts().is_empty());
}

/// NAN-4592: open through the production constructor with production
/// waits (the fixture's 150 ms ingest wait is for the drain test above) and
/// tick until the state stamps.
async fn open_stamping<'f>(f: &'f Fixture, work: &str, now: &mut i64) -> Ingestor<'f> {
    let mut i = f.open(work, true, false, *now).await;
    i.cfg.prevalence_ingest_wait = PREVALENCE_INGEST_WAIT;
    i.cfg.prevalence_stamp_wait = PREVALENCE_STAMP_WAIT;
    let deadline = Instant::now() + Duration::from_secs(60);
    while i.prevalence_status() != "stamping" {
        i.tick(*now).await.unwrap();
        *now += 500;
        assert!(Instant::now() < deadline, "never reached stamping: {}", i.prevalence_status());
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    i
}

/// NAN-4592: seal the owed hours and tick until every one is restamped.
async fn drain_owed(i: &mut Ingestor<'_>, now: &mut i64) {
    *now = (*now).max(START + 2 * HOUR);
    let deadline = Instant::now() + Duration::from_secs(120);
    while !i.prevalence_owed_hours().is_empty() {
        i.tick(*now).await.unwrap();
        *now += 1_000;
        assert!(i.restamp_retry.is_empty(), "an owed restamp failed");
        assert!(Instant::now() < deadline, "owed hours never restamped: {:?}", i.prevalence_owed_hours());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(i.health.prevalence_restamp_given_up_total, 0);
}

/// NAN-4592: a batch whose lookups are slow holds admission for the stamp
/// wait (1 s), not the 5 s ingest wait, and what it writes is the late-stamp
/// contract: every row committed unstamped, its hour owed, and the hour's
/// restamp later stamps exactly those rows (the late reads stamp nothing;
/// rows stamped on arrival are never changed).
#[tokio::test]
async fn slow_lookup_commits_unstamped_within_the_stamp_wait_and_owes_its_hour() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    let f = Fixture::new();
    let mut now = START;
    let mut i = open_stamping(&f, "late", &mut now).await;
    let lookup = Duration::from_secs(3);
    // Control, as before NAN-4592 (the stamp waited the whole ingest wait):
    // a 3 s lookup holds admission ~3 s and stamps the batch.
    i.cfg.prevalence_stamp_wait = PREVALENCE_INGEST_WAIT;
    i.prevalence.as_mut().unwrap().stamp_delay = Some(lookup);
    let unstamped = i.health.prevalence_unstamped_batches_total;
    f.source(40_000, now, 50, false, 80_000);
    let at = Instant::now();
    assert_eq!(i.tick(now).await.unwrap().admitted_rows, 50);
    let old_hold = at.elapsed();
    i.flush_now(now).await.unwrap();
    assert!(old_hold >= lookup, "control: the old wait held admission for the lookup ({old_hold:?})");
    assert_eq!(i.health.prevalence_unstamped_batches_total, unstamped, "control batch is stamped");
    assert!(i.prevalence_owed_hours().is_empty());
    // NAN-4592: the production stamp wait.
    i.cfg.prevalence_stamp_wait = PREVALENCE_STAMP_WAIT;
    now += 35_000;
    f.source(40_001, now, 50, false, 80_000);
    let at = Instant::now();
    assert_eq!(i.tick(now).await.unwrap().admitted_rows, 50);
    let held = at.elapsed();
    i.flush_now(now).await.unwrap();
    eprintln!("slow lookup ({lookup:?}): admission held {old_hold:?} before, {held:?} with the stamp wait");
    assert!(held < PREVALENCE_INGEST_WAIT / 2, "admission no longer waits the ingest wait: {held:?}");
    assert!(held < old_hold, "the stamp wait cuts the hold: {held:?} vs {old_hold:?}");
    assert_eq!(i.health.prevalence_unstamped_batches_total, unstamped + 1, "the late batch is unstamped");
    let hour = event_hour_of((now - 80_000 - 2_000) * 1_000);
    assert_eq!(i.prevalence_owed_hours(), vec![hour], "the late batch's hour is owed a restamp");
    assert!(i.prevalence_lookup.is_some(), "the late reads keep running in the background, warming the cache");
    // The late reads finish; their result is dropped, never stamped.
    tokio::time::sleep(lookup).await;
    i.tick(now).await.unwrap();
    assert!(i.prevalence_lookup.is_none());
    assert_eq!(i.health.prevalence_restamped_rows_total, 0);
    // Lookups stay slow; the owed hour's restamp (its own lookups) stamps
    // exactly the 50 late rows, not the 50 stamped on arrival.
    drain_owed(&mut i, &mut now).await;
    assert_eq!(i.health.prevalence_restamped_rows_total, 50);
    quiet(&mut i, &mut now, false).await;
    i.prevalence.take().unwrap().close().await.unwrap();
}

/// NAN-4592 convergence: with every lookup slower than the stamp wait, a
/// backlog of sources plus steady arrivals drains to zero lag with every
/// tick bounded by the stamp wait (not the 5 s ingest wait), every committed
/// row reaches the state, and the owed restamps then complete while lookups
/// are still slow.
#[tokio::test]
async fn backlog_drains_while_lookups_are_slow_and_owed_restamps_complete() {
    let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.write().await;
    const BACKLOG: usize = 12;
    const ARRIVALS: usize = 8;
    const ROWS_EACH: usize = 200;
    let f = Fixture::new();
    let mut now = START;
    let mut i = open_stamping(&f, "backlog", &mut now).await;
    // A tenant that has stamped before (its lake schema carries the stamp
    // columns a restamp fills; a schema without them is never restamped).
    f.source(49_999, now, ROWS_EACH, false, 80_000);
    let mut admitted = i.tick(now).await.unwrap().admitted_rows;
    i.flush_now(now).await.unwrap();
    assert_eq!(i.health.prevalence_unstamped_batches_total, 0);
    // Slower than the stamp wait, inside the old ingest wait: before
    // NAN-4592 every batch held admission ~4 s.
    i.prevalence.as_mut().unwrap().stamp_delay = Some(Duration::from_secs(4));
    for n in 0..BACKLOG {
        f.source(50_000 + n, now, ROWS_EACH, false, 80_000);
    }
    let (mut ticks, mut arrivals, mut worst) = (0, 0, Duration::ZERO);
    loop {
        if arrivals < ARRIVALS {
            f.source(60_000 + arrivals, now, ROWS_EACH, false, 2_000);
            arrivals += 1;
        }
        let at = Instant::now();
        admitted += i.tick(now).await.unwrap().admitted_rows;
        i.flush_now(now).await.unwrap();
        worst = worst.max(at.elapsed());
        // A tick may admit several groups; an overrun spell waits at most
        // `PREVALENCE_ADMIT_OVERRUN_WAITS` stamp waits in all (before
        // NAN-4592: that many 5 s ingest waits, each held ~4 s here).
        let bound = PREVALENCE_STAMP_WAIT * PREVALENCE_ADMIT_OVERRUN_WAITS + Duration::from_millis(500);
        assert!(at.elapsed() < bound, "a slow lookup held the tick {:?}", at.elapsed());
        now += 1_000;
        ticks += 1;
        if arrivals == ARRIVALS && admitted == ((1 + BACKLOG + ARRIVALS) * ROWS_EACH) as u64 {
            break;
        }
        assert!(ticks < 60, "backlog did not drain: {admitted} rows admitted");
    }
    i.tick(now).await.unwrap();
    assert_eq!(i.health.pending_notices, 0);
    assert_eq!(i.health.lag_ms, 0, "lag goes to zero");
    let unstamped = i.health.prevalence_unstamped_batches_total;
    assert!(unstamped > 0, "slow lookups left batches unstamped");
    assert!(!i.prevalence_owed_hours().is_empty());
    eprintln!("backlog of {BACKLOG} + {ARRIVALS} arrivals drained in {ticks} ticks, worst tick {worst:?}, {unstamped} unstamped batches");
    drain_owed(&mut i, &mut now).await;
    // Exactly the rows committed unstamped: everything but the first batch.
    assert_eq!(i.health.prevalence_restamped_rows_total, admitted - ROWS_EACH as u64);
    quiet(&mut i, &mut now, false).await;
    // Every committed Add reached the state: unstamped rows are counted too.
    let state = i.prevalence.as_ref().unwrap();
    let mut probe = serde_json::json!({"dst_endpoint":{"ip":"8.8.8.8"}});
    state.stamp(&mut probe).await.unwrap();
    assert_eq!(probe["enrichments"][0]["data"]["total_occurrences"], admitted);
    i.prevalence.take().unwrap().close().await.unwrap();
}
