// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit native benchmark; each case gets a fresh process because chDB's
//! engine configuration is process-global. All cases use
//! the same synthetic Parquet files, six CPU affinities and 1.5 GiB engine.
//! Run `nan4825_sixteen_agent_comparison` with --ignored --nocapture.

use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::planner::{NativeQueryPlan, QueryBudget};
use crate::thread_budget::ThreadBudget;
use std::time::{Duration, Instant};

const CORES: u64 = 6;
const SERVER: u64 = 3 << 29;
const FILES: usize = 36;
const AGENTS: usize = 16;
const HUNTS: usize = 8;

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

fn plan(sql: String) -> NativeQueryPlan {
    NativeQueryPlan {
        query_sha256: String::new(), sql, params: vec![],
        budget: QueryBudget { candidate_objects: FILES, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
        native_event_rows: false, temporary_aliases: Default::default(), schema_defaults: vec![], reader: Default::default(),
    }
}

fn hunt(class: u32, slots: usize) -> NativeQueryPlan {
    let dir = std::env::temp_dir().join("parts");
    plan(format!(
        "SELECT process, count() AS hits, uniqExact(hostname) AS hosts \
         FROM file('{}/part-*.parquet', Parquet) WHERE class_uid = {class} AND cmd LIKE '%flag%' \
         GROUP BY process ORDER BY hits DESC, process LIMIT 100 SETTINGS max_threads={CORES}, \
         max_memory_usage={}, max_execution_time=120", dir.display(), SERVER / slots as u64))
}

async fn streamed(executor: &NativeExecutor, plan: NativeQueryPlan) -> Vec<u8> {
    let mut stream = executor.execute_streaming(plan).await.unwrap();
    let mut data = Vec::new();
    while let Some(block) = stream.next().await { data.extend(block.unwrap().data); }
    data
}

fn quantile(samples: &mut [f64], fraction: f64) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[((samples.len() as f64 * fraction).ceil() as usize).clamp(1, samples.len()) - 1]
}

fn cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a valid rusage into the allocated struct.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) }, 0);
    let usage = unsafe { usage.assume_init() };
    usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1e6
        + usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1e6
}

#[tokio::test]
#[ignore = "native benchmark child; run nan4825_sixteen_agent_comparison"]
async fn seed() {
    let dir = std::env::temp_dir().join("parts");
    std::fs::create_dir_all(&dir).unwrap();
    let executor = NativeExecutor::start_with_server_memory_limit(runtime(), 1, "seed", ExecutorMode::ReadWrite, Some(SERVER)).unwrap();
    let extra = (0..12).map(|n| format!(", concat('value-', toString(cityHash64(number, {}) % 1024)) AS extra_{n}", n + 5)).collect::<String>();
    for file in 0..FILES {
        executor.execute_sql(format!(
            "INSERT INTO FUNCTION file('{}', Parquet) SELECT number AS time, \
             [1007,4001,4003,3002,1001,4002][1 + cityHash64(number,1) % 6] AS class_uid, \
             concat('host-', toString(cityHash64(number,2) % 2500)) AS hostname, \
             concat('proc-', toString(cityHash64(number,3) % 400), '.exe') AS process, \
             concat('C:/Windows/System32/', toString(cityHash64(number,4)), ' --flag ', toString(number)) AS cmd \
             {extra} FROM numbers({}, 100000) SETTINGS max_threads=4, output_format_parquet_row_group_size=50000",
            dir.join(format!("part-{file:03}.parquet")).display(), file * 100_000), vec![]).await.unwrap();
    }
}

async fn run_case(name: &str, slots: usize, role_pool: bool) {
    let threads = if role_pool {
        crate::part_query::memory_budget::QueryMemoryBudget::derive_for_role(2 << 30, None, CORES as u32 * 1000).threads as u64
    } else { CORES };
    let budget = ThreadBudget::new(threads);
    let executor = NativeExecutor::start_with_role_limits(runtime(), slots, "bench", ExecutorMode::ReadOnly, Some(SERVER), role_pool.then_some(threads))
        .unwrap().with_thread_budget(budget.clone());
    // Every request must match its warmed reference bytes, across schedulers.
    let mut references = Vec::new();
    for class in [1007, 4001, 4003, 3002, 1001] {
        let data = crate::query_timing::measure("warm", async { Ok::<_, ()>(streamed(&executor, hunt(class, slots)).await) }).await.unwrap();
        assert!(!data.is_empty());
        references.push(data);
    }
    let references = std::sync::Arc::new(references);
    // Separate fixed statement setup from native Parquet initialization and
    // scan time. Connections are resident in both comparison cases.
    let mut fixed = Vec::new();
    for _ in 0..32 {
        let timings = crate::query_timing::measure("fixed", async {
            streamed(&executor, plan("SELECT 1 SETTINGS max_threads=6".into())).await;
            let p = crate::query_timing::current().unwrap();
            let p = p.lock().unwrap();
            Ok::<_, ()>((p.native_init_abi_ms, p.native_bind_ms, p.sql_prepare_ms, p.native_session_reused))
        }).await.unwrap();
        assert_eq!(timings.3, 1, "successful statements must reuse their session");
        fixed.push(timings);
    }
    if role_pool {
        let metadata = executor.execute_sql("SELECT name,value FROM system.server_settings WHERE name IN ('max_thread_pool_size','max_thread_pool_free_size')".into(), vec![]).await.unwrap();
        let rows = String::from_utf8(metadata.data).unwrap();
        assert_eq!(rows.lines().count(), 2);
        for row in rows.lines() {
            let row: serde_json::Value = serde_json::from_str(row).unwrap();
            assert_eq!(row["value"], crate::executor::role_global_pool_threads(threads).to_string(), "first-connection pool settings were ignored");
        }
        let points = NativeExecutor::start_with_role_limits(runtime(), 1, "points", ExecutorMode::ReadOnly, Some(SERVER), Some(CORES)).unwrap();
        assert!(points.execute_sql("SELECT missing_column".into(), vec![]).await.is_err());
        assert!(!streamed(&points, plan("SELECT 42".into())).await.is_empty(), "recycled resident connection did not recover");
        // Existing priority/grant and agent lane protection remain in force.
        let agents = (0..AGENTS).map(|n| {
            let executor = executor.clone();
            tokio::spawn(async move {
                crate::query_timing::measure(&format!("agent-reserve-{n}"), executor.execute(plan("SELECT sleep(0.2) SETTINGS max_threads=1".into()))).await.unwrap();
            })
        }).collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(5), async {
            while executor.agent_slots().0 < slots - 1 { tokio::task::yield_now().await; }
        }).await.unwrap();
        let at = Instant::now();
        crate::query_timing::measure("analyst", executor.execute(plan("SELECT 1 SETTINGS max_threads=6".into()))).await.unwrap();
        assert!(at.elapsed() < Duration::from_millis(500), "analyst lane waited {:?}", at.elapsed());
        for agent in agents { agent.await.unwrap(); }
    }
    let cpu = cpu_seconds();
    let at = Instant::now();
    let agents = (0..AGENTS).map(|agent| {
        let executor = executor.clone();
        let references = references.clone();
        tokio::spawn(async move {
            let mut samples = Vec::new();
            for n in 0..HUNTS {
                let index = (agent + n) % 5;
                let at = Instant::now();
                samples.push(crate::query_timing::measure(&format!("agent-{agent}-{n}"), async {
                    let data = streamed(&executor, hunt([1007,4001,4003,3002,1001][index], slots)).await;
                    assert_eq!(data, references[index], "scheduler changed query rows");
                    let p = crate::query_timing::current().unwrap();
                    let p = p.lock().unwrap();
                    Ok::<_, ()>((at.elapsed().as_secs_f64() * 1000.0, p.lane_wait_ms, p.native_init_abi_ms, p.sql_prepare_ms))
                }).await.unwrap());
            }
            samples
        })
    }).collect::<Vec<_>>();
    let mut samples = Vec::new();
    for agent in agents { samples.extend(agent.await.unwrap()); }
    let wall = at.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu;
    let percentile = |column: usize, q| quantile(&mut samples.iter().map(|s| [s.0,s.1,s.2,s.3][column]).collect::<Vec<_>>(), q);
    let fixed_median = |column: usize| quantile(&mut fixed.iter().map(|s| [s.0,s.1,s.2][column]).collect::<Vec<_>>(), 0.5);
    use sha2::{Digest, Sha256};
    let checksum = format!("{:x}", Sha256::digest(references.concat()));
    println!("NAN4825_BENCH {}", serde_json::json!({
        "case": name, "agents": AGENTS, "queries": samples.len(), "slots": slots, "cores": CORES, "query_threads": threads,
        "qps": samples.len() as f64 / wall, "p50_ms": percentile(0,0.5), "p95_ms": percentile(0,0.95),
        "lane_wait_p95_ms": percentile(1,0.95), "native_init_p50_ms": percentile(2,0.5),
        "sql_prepare_p50_ms": percentile(3,0.5), "cpu_seconds_per_query": cpu / samples.len() as f64,
        "fixed_select1_native_init_p50_ms": fixed_median(0), "fixed_select1_bind_p50_ms": fixed_median(1),
        "fixed_select1_sql_prepare_p50_ms": fixed_median(2), "reference_sha256": checksum,
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
#[ignore = "native benchmark child; run nan4825_sixteen_agent_comparison"]
async fn legacy_one_slot() { run_case("legacy_one_slot", 1, false).await; }

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
#[ignore = "native benchmark child; run nan4825_sixteen_agent_comparison"]
async fn legacy_cpu_slots() { run_case("legacy_cpu_slots", 3, false).await; }

#[tokio::test(flavor = "multi_thread", worker_threads = 5)]
#[ignore = "native benchmark child; run nan4825_sixteen_agent_comparison"]
async fn role_pool() { run_case("role_pool", 3, true).await; }

#[test]
#[ignore = "native benchmark: verified chDB library and at least six CPUs"]
fn nan4825_sixteen_agent_comparison() {
    // Pin all children before their runtimes/native pools start. A build
    // VM's extra cores cannot make the comparison look faster.
    let mut mask = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    assert_eq!(unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) }, 0);
    let cpus = (0..libc::CPU_SETSIZE as usize).filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &mask) }).take(CORES as usize).collect::<Vec<_>>();
    assert_eq!(cpus.len(), CORES as usize, "run on an eight-CPU farm VM");
    unsafe { libc::CPU_ZERO(&mut mask); }
    for cpu in &cpus { unsafe { libc::CPU_SET(*cpu, &mut mask); } }
    assert_eq!(unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) }, 0);
    println!("NAN4825_CPU_AFFINITY {cpus:?}");
    let dir = tempfile::tempdir().unwrap();
    let mut rows = Vec::new();
    for case in ["seed", "legacy_one_slot", "legacy_cpu_slots", "role_pool"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", &format!("query_capacity_native_tests::{case}"), "--nocapture", "--test-threads=1"])
            .env("TMPDIR", dir.path()).output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("{stdout}");
        assert!(output.status.success(), "{case} failed: {stderr}");
        if let Some((_, json)) = stdout.split_once("NAN4825_BENCH ") {
            rows.push(serde_json::from_str::<serde_json::Value>(json.lines().next().unwrap()).unwrap());
        }
    }
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["reference_sha256"], rows[1]["reference_sha256"]);
    assert_eq!(rows[0]["reference_sha256"], rows[2]["reference_sha256"]);
    let before = rows[0]["p95_ms"].as_f64().unwrap();
    let after = rows[2]["p95_ms"].as_f64().unwrap();
    assert!(after < before, "sixteen-agent p95 did not improve: before {before}, after {after}");
}
