// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4174, native: the thread budget as chDB sees it. Each statement
//! reports the `max_threads` / `max_parsing_threads` chDB actually ran it
//! with, through the real executor (and the real lane router), while other
//! statements hold their grants.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=...
//! cargo test -p nanosiem-lake-worker --lib thread_budget::native -- --ignored --nocapture --test-threads=1
//! ```

use super::{Priority, ThreadBudget};
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::planner::NativeQueryPlan;
use std::sync::Arc;
use std::time::Duration;

const POOL: u64 = 6;

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

fn pool(runtime: &NativeChdb, lanes: usize, name: &str, budget: &Arc<ThreadBudget>) -> NativeExecutor {
    NativeExecutor::start_with_server_memory_limit(runtime.clone(), lanes, name, ExecutorMode::ReadOnly, Some(3 << 30))
        .unwrap()
        .with_thread_budget(budget.clone())
}

/// A statement that reports its effective thread settings after `sleep_s`,
/// planned at 8 threads (more than the pool).
fn probe(sleep_s: f64) -> NativeQueryPlan {
    NativeQueryPlan {
        query_sha256: String::new(),
        sql: format!(
            "SELECT toUInt64(getSetting('max_threads')) AS threads, toUInt64(getSetting('max_parsing_threads')) AS parsing, \
             sleep({sleep_s}) AS slept SETTINGS max_threads=8, max_execution_time=30"
        ),
        params: vec![],
        budget: crate::planner::QueryBudget { candidate_objects: 1, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
        native_event_rows: false,
        temporary_aliases: Default::default(),
        schema_defaults: vec![],
        reader: Default::default(),
    }
}

/// `(threads, parsing threads)` chDB ran `plan` with.
async fn threads_of(executor: &NativeExecutor, plan: NativeQueryPlan) -> (u64, u64) {
    let output = executor.execute(plan).await.unwrap();
    parse(&output.data)
}

fn parse(data: &[u8]) -> (u64, u64) {
    let row: serde_json::Value = serde_json::from_slice(data.split(|b| *b == b'\n').next().unwrap()).unwrap();
    let number = |name: &str| row[name].as_u64().or_else(|| row[name].as_str().and_then(|v| v.parse().ok())).unwrap();
    (number("threads"), number("parsing"))
}

async fn as_request<T>(request_id: &str, work: impl std::future::Future<Output = T>) -> T {
    crate::query_timing::measure(request_id, async { Ok::<_, ()>(work.await) }).await.unwrap()
}

/// Wait until `budget` holds `(interactive, companion, background)` grants.
async fn until_running(budget: &ThreadBudget, expected: (u64, u64, u64)) {
    for _ in 0..500 {
        if budget.running() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("budget never reached {expected:?}: {:?}", budget.running());
}

/// Fair sharing: a lone interactive statement runs on the whole pool (not
/// the old fixed 4); one started beside it gets the NAN-4772 slack (its half
/// share, lowered to the room left), a third waits for room and then gets
/// its share; once they end the next lone statement has the whole pool
/// again. Every grant also bounds chDB's Parquet parsing pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn interactive_statements_share_the_pool_fairly() {
    let budget = ThreadBudget::new(POOL);
    let executor = pool(&runtime(), 4, "parts", &budget);
    assert_eq!(as_request("user-a", threads_of(&executor, probe(0.0))).await, (POOL, POOL));

    let (first_executor, second_executor) = (executor.clone(), executor.clone());
    let first = tokio::spawn(async move { as_request("user-a", threads_of(&first_executor, probe(2.0))).await });
    until_running(&budget, (1, 0, 0)).await;
    let second = tokio::spawn(async move { as_request("user-b", threads_of(&second_executor, probe(1.5))).await });
    until_running(&budget, (2, 0, 0)).await;
    let started = std::time::Instant::now();
    let third = as_request("user-c", threads_of(&executor, probe(0.0))).await;
    assert!(started.elapsed() >= Duration::from_millis(1_000), "no room: it waited for user-b ({:?})", started.elapsed());
    assert_eq!(third, (POOL / 3, POOL / 3), "beside user-a's whole pool: what the bound leaves");
    let slack = super::INTERACTIVE_SLACK_THREADS;
    assert_eq!(second.await.unwrap(), (slack, slack), "beside a lone whole-pool statement: the slack");
    assert_eq!(first.await.unwrap(), (POOL, POOL), "alone when it started");
    until_running(&budget, (0, 0, 0)).await;
    assert_eq!(as_request("user-a", threads_of(&executor, probe(0.0))).await, (POOL, POOL));
    // A histogram companion takes at most two, beside its own primary too.
    assert_eq!(as_request("user-a-hist", threads_of(&executor, probe(0.0))).await, (2, 2));
}

/// Priority: background work (outside any request: a durable bare-* or
/// retro job, a partial build; or a `detect-` request) takes half the pool
/// on an idle process, never shrinks an interactive statement, and gets a
/// single thread while anything interactive runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn background_work_yields_to_interactive_statements() {
    let budget = ThreadBudget::new(POOL);
    let runtime = runtime();
    let lanes = pool(&runtime, 4, "parts", &budget);
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 30))
        .unwrap()
        .with_thread_budget(budget.clone());
    assert_eq!(Priority::current(), Priority::Background);

    // A job alone on an idle process: half the pool.
    let job_writer = writer.clone();
    let job = tokio::spawn(async move { threads_of(&job_writer, probe(2.0)).await });
    until_running(&budget, (0, 0, 1)).await;
    // An interactive statement beside the job still gets the whole pool.
    let user_lanes = lanes.clone();
    let user = tokio::spawn(async move { as_request("user-a", threads_of(&user_lanes, probe(1.5))).await });
    until_running(&budget, (1, 0, 1)).await;
    // A job (or a scheduled detection request) starting now gets one thread.
    let late_job = threads_of(&lanes, probe(0.0)).await;
    let detection = as_request("detect-0192", threads_of(&lanes, probe(0.0))).await;
    assert_eq!((late_job, detection), ((1, 1), (1, 1)));
    assert_eq!(user.await.unwrap(), (POOL, POOL), "a running job never shrinks interactive work");
    assert_eq!(job.await.unwrap(), (POOL / 2, POOL / 2), "an idle-process job leaves half the pool free");
    until_running(&budget, (0, 0, 0)).await;
    assert_eq!(threads_of(&lanes, probe(0.0)).await, (POOL / 2, POOL / 2));
}

/// NAN-4738: agent-class statements (`agent-` request ids) never shrink an
/// analyst: an analyst starting beside running agent statements gets the
/// whole pool, an agent statement starting beside an analyst gets one thread,
/// and agents alone share a quarter of the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn agent_statements_never_shrink_an_analyst() {
    let budget = ThreadBudget::new(8);
    let executor = pool(&runtime(), 4, "parts", &budget);
    let (first_executor, second_executor) = (executor.clone(), executor.clone());
    let first = tokio::spawn(async move { as_request("agent-1", threads_of(&first_executor, probe(2.0))).await });
    for _ in 0..500 {
        if budget.running_agents() == 1 { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = tokio::spawn(async move { as_request("agent-2-hist", threads_of(&second_executor, probe(1.5))).await });
    for _ in 0..500 {
        if budget.running_agents() == 2 { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(budget.running(), (0, 0, 0), "agent statements are not interactive");
    let analyst_executor = executor.clone();
    let analyst = tokio::spawn(async move { as_request("user-a", threads_of(&analyst_executor, probe(1.0))).await });
    until_running(&budget, (1, 0, 0)).await;
    let late_agent = as_request("agent-3", threads_of(&executor, probe(0.0))).await;
    assert_eq!(late_agent, (1, 1), "an agent beside an analyst gets one thread");
    assert_eq!(analyst.await.unwrap(), (8, 8), "an analyst beside agents keeps the whole pool");
    assert_eq!(second.await.unwrap(), (1, 1), "agents share their quarter");
    assert_eq!(first.await.unwrap(), (2, 2), "a lone agent: a quarter of the pool");
}

/// Through the lane router: with a budget the fixed 4-thread interactive
/// cap gives way to the pool, and a predictable 7 d string aggregate starts
/// on the large lane without a small-lane attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn router_takes_threads_from_the_budget_and_routes_large_aggregates_large() {
    use crate::part_query::lanes::{run_sized, LaneMemo, LargeLane};
    let budget = ThreadBudget::new(POOL);
    let runtime = runtime();
    let small = pool(&runtime, 2, "parts", &budget);
    let large = LargeLane::new(pool(&runtime, 2, "parts-large", &budget), 3 << 29);
    let memo = LaneMemo::default();
    let output = as_request("user-a", run_sized(&small, Some(&large), &memo, probe(0.0))).await.unwrap();
    assert_eq!(parse(&output.data), (POOL, POOL), "a lone statement is no longer capped at 4");
    assert_eq!((small.status().completed, large.executor().status().completed), (1, 0));

    let mut aggregate = probe(0.0);
    aggregate.query_sha256 = "b".repeat(64);
    aggregate.reader = crate::planner::ReaderShape { string_group_by: true, window_class: 8, ..Default::default() };
    let output = as_request("user-a", run_sized(&small, Some(&large), &memo, aggregate)).await.unwrap();
    assert_eq!(parse(&output.data), (POOL, POOL));
    assert_eq!((small.status().completed, small.status().failed, large.executor().status().completed), (1, 0, 1),
        "the predicted aggregate ran once, on the large lane");
    assert_eq!(memo.len(), 0, "a prediction is not an escalation");
}

/// NAN-4742, native: 16 concurrent agent statements on the production
/// 6-lane executor hold at most five lanes, so an analyst statement started
/// beside them runs at once (not after an agent's second-long statement),
/// and every agent statement still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn sixteen_agent_statements_leave_an_analyst_a_lane() {
    let budget = ThreadBudget::new(8);
    let executor = pool(&runtime(), 6, "parts", &budget);
    let agents = (0..16)
        .map(|n| {
            let executor = executor.clone();
            tokio::spawn(async move { as_request(&format!("agent-{n}"), threads_of(&executor, probe(1.0))).await })
        })
        .collect::<Vec<_>>();
    for _ in 0..500 {
        if budget.running_agents() == 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(executor.agent_slots(), (5, 5));
    assert_eq!(budget.running_agents(), 5, "five agent statements run; the rest wait for a slot");
    let started = std::time::Instant::now();
    let analyst = as_request("user-a", threads_of(&executor, probe(0.0))).await;
    assert!(started.elapsed() < Duration::from_millis(500), "the analyst waited {:?}", started.elapsed());
    assert_eq!(analyst, (8, 8), "and kept the whole pool");
    for agent in agents {
        agent.await.unwrap();
    }
    // The lane replies before it drops the agent slot (NAN-4772 review P3:
    // reading it right after the last reply raced the drop).
    for _ in 0..200 {
        if executor.agent_slots().0 == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(executor.agent_slots(), (0, 5));
}

/// Process CPU seconds so far (user + system, every thread).
fn process_cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    // SAFETY: zero-initialized and filled above.
    let usage = unsafe { usage.assume_init() };
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// NAN-4772 bench (not a pass/fail test): the Mythos 1.0.12 throughput
/// shape on the production executor and thread budget. Sixteen closed-loop
/// agents, each running ten class-filtered aggregates (`count()` and an
/// exact `uniqExact` by process over 36 Parquet files), on a six-lane
/// executor with a six-thread pool. Prints q/s, p50/p95 and core-seconds
/// per hunt; pin the process to the pool's cores so the CPU matches a
/// six-core role:
///
/// ```sh
/// taskset -c 0-5 cargo test -p nanosiem-lake-worker --lib thread_budget::native::bench_ -- --ignored --nocapture --test-threads=1
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "native bench: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn bench_sixteen_closed_loop_agents_on_a_six_thread_pool() {
    const FILES: usize = 36;
    const AGENTS: usize = 16;
    const HUNTS: usize = 10;
    let runtime = runtime();
    let dir = std::env::temp_dir().join("nan4772-bench");
    std::fs::create_dir_all(&dir).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 30)).unwrap();
    for file in 0..FILES {
        let path = dir.join(format!("part-{file:03}.parquet"));
        if path.exists() {
            continue;
        }
        let sql = format!(
            "INSERT INTO FUNCTION file('{}', Parquet) SELECT number AS time, \
             [1007, 4001, 4003, 3002, 1001, 4002][1 + cityHash64(number, 1) % 6] AS class_uid, \
             concat('host-', toString(cityHash64(number, 2) % 2500)) AS hostname, \
             concat('proc-', toString(cityHash64(number, 3) % 400), '.exe') AS process, \
             concat('C:\\\\Windows\\\\System32\\\\', toString(cityHash64(number, 4)), ' --flag ', toString(number)) AS cmd \
             FROM numbers({}, 200000) SETTINGS max_threads=4, output_format_parquet_row_group_size=50000",
            path.display(), file * 200_000);
        writer.execute_sql(sql, vec![]).await.unwrap();
    }
    let budget = ThreadBudget::new(POOL);
    let executor = pool(&runtime, 6, "parts", &budget);
    let dir = dir.display().to_string();
    let hunt = move |class: u32| NativeQueryPlan {
        query_sha256: String::new(),
        sql: format!(
            "SELECT process, count() AS hits, uniqExact(hostname) AS hosts, toUInt64(getSetting('max_threads')) AS threads \
             FROM file('{dir}/part-*.parquet', Parquet) WHERE class_uid = {class} AND cmd LIKE '%flag%' \
             GROUP BY process ORDER BY hits DESC, process LIMIT 100 SETTINGS max_threads={POOL}, max_execution_time=120"),
        params: vec![],
        budget: crate::planner::QueryBudget { candidate_objects: FILES, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
        native_event_rows: false,
        temporary_aliases: Default::default(),
        schema_defaults: vec![],
        reader: Default::default(),
    };
    // Warm the page cache and chDB's metadata.
    as_request("warm", executor.execute(hunt(1007))).await.unwrap();
    let cpu = process_cpu_seconds();
    let started = std::time::Instant::now();
    let agents = (0..AGENTS)
        .map(|agent| {
            let executor = executor.clone();
            let hunt = hunt.clone();
            tokio::spawn(async move {
                let mut samples = Vec::new();
                for n in 0..HUNTS {
                    let class = [1007, 4001, 4003, 3002, 1001][(agent + n) % 5];
                    let at = std::time::Instant::now();
                    let output = as_request(&format!("bench-{agent}-{n}"), executor.execute(hunt(class))).await.unwrap();
                    let row: serde_json::Value = serde_json::from_slice(output.data.split(|b| *b == b'\n').next().unwrap()).unwrap();
                    let threads = row["threads"].as_u64().or_else(|| row["threads"].as_str().and_then(|v| v.parse().ok())).unwrap();
                    samples.push((at.elapsed().as_secs_f64() * 1000.0, threads));
                }
                samples
            })
        })
        .collect::<Vec<_>>();
    let mut samples = Vec::new();
    for agent in agents {
        samples.extend(agent.await.unwrap());
    }
    let wall = started.elapsed().as_secs_f64();
    let cpu = process_cpu_seconds() - cpu;
    let mut latency = samples.iter().map(|(ms, _)| *ms).collect::<Vec<_>>();
    latency.sort_by(f64::total_cmp);
    let rank = |q: f64| latency[((q * latency.len() as f64).ceil() as usize).clamp(1, latency.len()) - 1];
    let mut by_threads = std::collections::BTreeMap::<u64, usize>::new();
    for (_, threads) in &samples {
        *by_threads.entry(*threads).or_default() += 1;
    }
    println!(
        "NAN-4772 bench: {} hunts, {:.2} q/s, p50 {:.0} ms, p95 {:.0} ms, core-s/hunt {:.3}, avg cores {:.2}, statements by threads {:?}",
        samples.len(), samples.len() as f64 / wall, rank(0.50), rank(0.95), cpu / samples.len() as f64, cpu / wall, by_threads);
}

/// NAN-4772 (review P1): N concurrent analyst statements on the production
/// executor never hold more than the pool plus the slack, every one runs
/// (at least one thread each), and the floor still applies while there is
/// room.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn concurrent_analyst_grants_stay_within_the_bound() {
    const ANALYSTS: usize = 6;
    let budget = ThreadBudget::new(POOL);
    let executor = pool(&runtime(), 6, "parts", &budget);
    let bound = POOL + super::INTERACTIVE_SLACK_THREADS;
    let analysts = (0..ANALYSTS)
        .map(|n| {
            let executor = executor.clone();
            tokio::spawn(async move { as_request(&format!("user-{n}"), threads_of(&executor, probe(0.4))).await })
        })
        .collect::<Vec<_>>();
    let mut peak = 0;
    while analysts.iter().any(|analyst| !analyst.is_finished()) {
        peak = peak.max(budget.interactive_threads());
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let mut grants = Vec::new();
    for analyst in analysts {
        grants.push(analyst.await.unwrap().0);
    }
    println!("NAN-4772 {ANALYSTS} analysts on a {POOL}-thread pool: grants {grants:?}, peak held {peak} (bound {bound})");
    assert!(peak <= bound, "held {peak} > {bound}");
    assert!(peak > POOL, "the slack is used: a second analyst starts at once");
    assert!(grants.iter().all(|threads| *threads >= 1));
    assert_eq!(grants.len(), ANALYSTS);
    assert_eq!(budget.interactive_threads(), 0);
}

/// NAN-4772 (review P1): sixteen agents admitted through the real engine
/// take at most `slots - ANALYST_RESERVED_SLOTS` admission slots, so an
/// analyst is admitted at once while they run, and every agent completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn sixteen_agents_never_take_the_analyst_admission_slots() {
    use crate::part_query::engine::{yielding_permits, EngineSettings, PartQueryEngine, RequestClass, ANALYST_RESERVED_SLOTS};
    use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use crate::part_query::log_view::PartLogView;
    use crate::parts::part_log::{LocalObjectStore, ObjectStore};
    use crate::parts::provenance::TenantKeySet;
    use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TENANT: &str = "7a3c1e5b-2d4f-4b6a-8c9e-0f1a2b3c4d5e";
    let root = tempfile::tempdir().unwrap();
    let parts = root.path().join("parts");
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(&parts).unwrap());
    let keys = TenantKeySet::default();
    let view = PartLogView::open(store.as_ref(), TENANT, keys.clone()).await.unwrap();
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: root.path().join("cache"), max_bytes: 1 << 30, query_max_bytes: 1 << 29,
            fetch_concurrency: 4, fetch_deadline: Duration::from_secs(60),
        },
        TENANT, "nan4772-local", &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local("nan4772-local", store.clone(), parts)),
    ).unwrap();
    let fetcher = PartFetcher::new(TENANT, "nan4772-local", store.clone(), keys, cache).unwrap();
    let budget = ThreadBudget::new(POOL);
    let native = runtime();
    let executor = pool(&native, 6, "parts", &budget);
    let large = pool(&native, 2, "parts-large", &budget);
    let engine = Arc::new(PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(), bucket: "nan4772-local".into(), compiler: "unused".into(),
            max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20,
            max_execution_seconds: 120, threads: POOL,
        }, store, view, fetcher, executor.clone(),
    ).unwrap().with_large(large, 3 << 29));
    let slots = engine.admission_slots();
    assert_eq!(slots, 7);
    let agent_slots = yielding_permits(slots);
    assert_eq!(agent_slots, slots - ANALYST_RESERVED_SLOTS);
    let admitted = Arc::new(AtomicUsize::new(0));
    let agents = (0..16).map(|n| {
        let engine = engine.clone();
        let admitted = admitted.clone();
        tokio::spawn(async move {
            let request_id = format!("agent-{n}");
            assert_eq!(RequestClass::of(&request_id, false), RequestClass::Yielding);
            let _slot = engine.admit_class(RequestClass::of(&request_id, false), Duration::from_secs(30)).await.unwrap();
            admitted.fetch_add(1, Ordering::SeqCst);
            let output = as_request(&request_id, engine.run(probe(1.0))).await.unwrap();
            parse(&output.data)
        })
    }).collect::<Vec<_>>();
    for _ in 0..500 {
        if admitted.load(Ordering::SeqCst) == agent_slots && budget.running_agents() == agent_slots as u64 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(admitted.load(Ordering::SeqCst), agent_slots, "agents stop at their share of the slots");
    // Both reserved slots, held together beside the agents.
    let mut analysts = Vec::new();
    for n in 0..ANALYST_RESERVED_SLOTS {
        let started = std::time::Instant::now();
        let analyst = engine.admit_class(RequestClass::of(&format!("user-{n}"), false), Duration::from_millis(200)).await;
        assert!(started.elapsed() < Duration::from_millis(100), "at once ({:?})", started.elapsed());
        analysts.push(analyst.unwrap_or_else(|error| panic!("analyst {n} admitted beside {agent_slots} agents: {error}")));
    }
    drop(analysts);
    for agent in agents {
        agent.await.unwrap();
    }
    assert_eq!(admitted.load(Ordering::SeqCst), 16, "every agent ran");
}

/// Reviewer regressions: the streamed production route must use the same
/// admission class, including on the smallest role with size classes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn yielding_reserve_survives_small_roles_and_streamed_requests() {
    use crate::part_query::engine::{yielding_permits, EngineSettings, PartQueryEngine, RequestClass, ANALYST_RESERVED_SLOTS};
    use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use crate::part_query::log_view::PartLogView;
    use crate::part_query::{detections::DetectionGate, server::QueryService};
    use crate::parts::part_log::{LocalObjectStore, ObjectStore};
    use crate::parts::provenance::TenantKeySet;
    use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TENANT: &str = "7a3c1e5b-2d4f-4b6a-8c9e-0f1a2b3c4d5e";
    let native = runtime();
    for lanes in [6, 2] {
        let root = tempfile::tempdir().unwrap();
        let parts = root.path().join("parts");
        let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(&parts).unwrap());
        let keys = TenantKeySet::default();
        let view = PartLogView::open(store.as_ref(), TENANT, keys.clone()).await.unwrap();
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: root.path().join("cache"), max_bytes: 1 << 30, query_max_bytes: 1 << 29,
                fetch_concurrency: 4, fetch_deadline: Duration::from_secs(60),
            },
            TENANT, "review-local", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("review-local", store.clone(), parts)),
        ).unwrap();
        let fetcher = PartFetcher::new(TENANT, "review-local", store.clone(), keys, cache).unwrap();
        let budget = ThreadBudget::new(POOL);
        let engine = PartQueryEngine::new(
            EngineSettings {
                tenant_id: TENANT.into(), bucket: "review-local".into(), compiler: "unused".into(),
                max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20,
                max_execution_seconds: 120, threads: POOL,
            }, store, view, fetcher, pool(&native, lanes, "parts", &budget),
        ).unwrap().with_large(pool(&native, 1, "parts-large", &budget), 512 << 20);
        let service = QueryService::new(engine, DetectionGate::new(None, 0).unwrap(), root.path().join("service"),
            "a".repeat(64), "b".repeat(64), None, 0, None);
        service.mark_ready_without_prewarm();
        service.set_admission_deadline(Duration::from_millis(30));
        let engine = service.engine();
        let slots = engine.admission_slots();
        let mut yielding = Vec::new();
        for n in 0..yielding_permits(slots) {
            let id = if n % 2 == 0 { "agent-held" } else { "detect-held" };
            yielding.push(engine.admit_class(RequestClass::of(id, false), Duration::from_millis(30)).await.unwrap());
        }
        for id in ["agent-stream", "detect-stream"] {
            let body = serde_json::json!({
                "request_id": id, "tenant_id": TENANT, "dataset": "logs", "query": "*",
                "start": "2026-10-28T00:00:00Z", "end": "2026-10-28T01:00:00Z",
                "limit": 10, "table_view": false,
            }).to_string();
            let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
            let task = tokio::spawn(service.clone().serve_stream(server));
            client.write_all(format!(
                "POST /v1/query/pages?page_rows=10 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len(),
            ).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response)).await.unwrap().unwrap();
            task.await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 429 "), "{lanes} small lanes, {id}: {response}");
        }
        let mut analysts = Vec::new();
        for _ in 0..ANALYST_RESERVED_SLOTS {
            analysts.push(engine.admit_class(RequestClass::Primary, Duration::from_millis(30)).await.unwrap());
        }
        drop((analysts, yielding));
        // detect[T] gives back exactly the reserve, once, at either size.
        engine.serve_without_analysts();
        engine.serve_without_analysts();
        let mut detections = Vec::new();
        for _ in 0..slots {
            detections.push(engine.admit_class(RequestClass::Yielding, Duration::from_millis(30)).await.unwrap());
        }
        assert!(engine.admit_class(RequestClass::Yielding, Duration::from_millis(30)).await.is_err());
        drop(detections);
    }
}

/// Waiting for a thread grant is still queueing: a request abandoned there
/// must never enter chDB when another statement finally returns its grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn abandoned_analyst_waiting_for_threads_never_enters_native() {
    let native = runtime();
    for streaming in [false, true] {
        let budget = ThreadBudget::new(POOL);
        let executor = pool(&native, 1, "parts", &budget);
        let first = budget.grant(Priority::Interactive);
        let second = budget.grant(Priority::Interactive);
        let mut abandoned = tokio::spawn({
            let executor = executor.clone();
            async move {
                as_request("abandoned", async {
                    if streaming {
                        let _stream = executor.execute_streaming(probe(0.0)).await.unwrap();
                    } else {
                        threads_of(&executor, probe(0.0)).await;
                    }
                }).await;
            }
        });
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut abandoned).await.is_err());
        abandoned.abort();
        assert!(abandoned.await.unwrap_err().is_cancelled());
        drop((first, second));
        // One lane: this reply also proves the abandoned job has been handled.
        assert_eq!(as_request("live", threads_of(&executor, probe(0.0))).await, (POOL, POOL));
        assert_eq!(executor.status().completed, 1, "only the live statement entered chDB (streaming={streaming})");
    }
}
