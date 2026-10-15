// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3393, native: wide-text statements (a bareword hash verified against
//! `message`/`raw_data`) over many 65,536-row groups, run through the real
//! executor under the query role's lane caps.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=...
//! cargo test -p nanosiem-lake-worker --lib part_query::lanes::native -- --ignored --nocapture --test-threads=1
//! ```

use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::planner::NativeQueryPlan;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) const MIB: u64 = 1024 * 1024;
/// The part writer's row group (parts::format).
const GROUP_ROWS: usize = 65_536;
pub(super) const NEEDLE: &str = "0faafb1b35275f3912da163319c87e224985b26b36e662f813897f22445e187e";

pub(super) fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

/// A word stream with log-like redundancy (zstd ~5-8x, like the live text).
fn words(seed: u64, bytes: usize) -> String {
    const VOCAB: [&str; 24] = [
        "Image=C:\\Windows\\System32\\svchost.exe", "ParentImage=C:\\Windows\\explorer.exe", "User=CORP\\svc_dc",
        "LogonId=0x3e7", "IntegrityLevel=System", "CurrentDirectory=C:\\Windows\\system32\\", "TerminalSessionId=0",
        "GET", "/index.html", "HTTP/1.1", "200", "Mozilla/5.0", "(Windows NT 10.0; Win64; x64)", "RuleName=-",
        "EventType=CreateKey", "TargetObject=HKLM\\System\\CurrentControlSet\\Services", "Protocol=tcp",
        "Initiated=true", "SourceIsIpv6=false", "DestinationPort=443", "Company=Microsoft Corporation",
        "Product=Microsoft Windows Operating System", "FileVersion=10.0.19041.1", "Description=Host Process",
    ];
    let mut out = String::with_capacity(bytes + 64);
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    while out.len() < bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push_str(VOCAB[(state % VOCAB.len() as u64) as usize]);
        out.push(' ');
        if state % 5 == 0 {
            out.push_str(&format!("{:016x} ", state));
        }
    }
    out
}

/// `files` Parquet files of `groups` row groups each: time, metadata
/// (uid, log_source, event_code), a ~300 B `message` and a ~1 KiB
/// `raw_data`. Every 50,000th row carries [`NEEDLE`] in raw_data.
pub(super) fn write_fixture(dir: &Path, files: usize, groups: usize) -> Vec<PathBuf> {
    use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray};
    use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
    let metadata_fields = Fields::from(vec![
        Field::new("uid", DataType::Utf8, true),
        Field::new("log_source", DataType::Utf8, true),
        Field::new("event_code", DataType::Utf8, true),
    ]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())), false),
        Field::new("metadata", DataType::Struct(metadata_fields.clone()), true),
        Field::new("message", DataType::Utf8, true),
        Field::new("raw_data", DataType::Utf8, true),
    ]));
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
        .set_max_row_group_row_count(Some(GROUP_ROWS))
        .build();
    let mut paths = Vec::new();
    for file in 0..files {
        let path = dir.join(format!("data-{file:05}.parquet"));
        let mut writer =
            parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema.clone(), Some(props.clone()))
                .unwrap();
        for group in 0..groups {
            let base = (file * groups + group) * GROUP_ROWS;
            let rows = base..base + GROUP_ROWS;
            let time = TimestampMicrosecondArray::from_iter_values(rows.clone().map(|i| 1_791_000_000_000_000 + i as i64 * 100_000))
                .with_timezone("UTC");
            let uid = StringArray::from_iter_values(rows.clone().map(|i| format!("uid-{i:010}")));
            let source = StringArray::from_iter_values(rows.clone().map(|i| if i % 3 == 0 { "windows_sysmon" } else { "web_apache" }));
            let code = StringArray::from_iter_values(rows.clone().map(|i| format!("{}", 1 + i % 23)));
            let metadata = StructArray::new(
                metadata_fields.clone(),
                vec![Arc::new(uid) as ArrayRef, Arc::new(source), Arc::new(code)],
                None,
            );
            let message = StringArray::from_iter_values(rows.clone().map(|i| words(i as u64, 300)));
            let raw = StringArray::from_iter_values(rows.clone().map(|i| {
                let text = words(i as u64 ^ 0x5555, 1_000);
                if i % 50_000 == 7 { format!("{text} Hashes=SHA256={NEEDLE}") } else { text }
            }));
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![Arc::new(time), Arc::new(metadata), Arc::new(message), Arc::new(raw)],
            )
            .unwrap();
            writer.write(&batch).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        paths.push(path);
    }
    paths
}

pub(super) const READ_SCHEMA: &str = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String), `event_code` Nullable(String)), `message` Nullable(String), `raw_data` Nullable(String)";

/// The live bareword-hash statement shape (`<hash> | stats count by
/// metadata.event_code`) with the planner's hardened settings at `threads`
/// and a small lane's 256 MiB cap.
pub(super) fn hash_stats_sql(threads: u64, memory_bytes: u64) -> String {
    format!(
        "WITH stage_0 AS (SELECT message, \"metadata.event_code\", raw_data, time FROM (SELECT `message` AS `message`, \
         `metadata`.`event_code` AS `metadata.event_code`, `raw_data` AS `raw_data`, `time` AS `time` \
         FROM file({{source:String}}, Parquet, {{schema:String}})) \
         WHERE ((positionCaseInsensitive(message, '{NEEDLE}') > 0 AND hasAllTokens(lower(message), '{NEEDLE}')) \
         OR (positionCaseInsensitive(raw_data, '{NEEDLE}') > 0 AND hasAllTokens(lower(raw_data), '{NEEDLE}')))), \
         stage_1 AS (SELECT \"metadata.event_code\" AS \"metadata.event_code\", count() AS count FROM stage_0 GROUP BY \"metadata.event_code\") \
         SELECT * FROM stage_1 ORDER BY \"metadata.event_code\" \
         SETTINGS max_threads={threads}, max_execution_time=120, max_memory_usage={memory_bytes}, \
         max_bytes_before_external_sort={half}, max_bytes_before_external_group_by={half}, max_block_size=8192, \
         preferred_block_size_bytes=8388608, use_query_cache=0, input_format_parquet_allow_missing_columns=1, \
         input_format_parquet_filter_push_down=1, input_format_parquet_bloom_filter_push_down=1",
        half = memory_bytes / 2
    )
}

pub(super) fn plan(sql: String, source: &str) -> NativeQueryPlan {
    NativeQueryPlan {
        query_sha256: String::new(),
        sql,
        params: vec![("source".into(), source.into()), ("schema".into(), READ_SCHEMA.into())],
        budget: crate::planner::QueryBudget { candidate_objects: 1, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
        native_event_rows: false,
        temporary_aliases: Default::default(),
        schema_defaults: vec![], reader: Default::default(),
    }
}

pub(super) fn source_glob(paths: &[PathBuf]) -> String {
    let dir = paths[0].parent().unwrap().to_str().unwrap();
    format!("{dir}/data-*.parquet")
}

pub(super) fn fixture_dir() -> PathBuf {
    let root = std::env::var_os("NAN3393_FIXTURE_DIR").map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("nan3393-lanes"));
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// The shared fixture: 24 files x 4 row groups (~1.3 GB compressed text).
pub(super) fn fixture(dir: &Path) -> Vec<PathBuf> {
    const FILES: usize = 24;
    let paths = (0..FILES).map(|i| dir.join(format!("data-{i:05}.parquet"))).collect::<Vec<_>>();
    if paths.iter().all(|path| path.exists()) { paths } else { write_fixture(dir, FILES, 4) }
}

/// Exploration: the smallest statement cap each setting variant fits in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "probe: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn probe_wide_text_reader_memory() {
    let dir = fixture_dir();
    let paths = fixture(&dir);
    let source = source_glob(&paths);
    let executor = NativeExecutor::start_with_server_memory_limit(runtime(), 1, "parts", ExecutorMode::ReadOnly, Some(3 << 30)).unwrap();
    let defaults = executor
        .execute_sql("SELECT name, value FROM system.settings WHERE name LIKE 'input_format_parquet%' FORMAT TSV".into(), vec![])
        .await
        .unwrap();
    eprintln!("{}", String::from_utf8_lossy(&defaults.data));
    let reader = |threads: u64, block: u64, prefer: u64, watermark: u64| move |sql: String| {
        let mut sql = super::lower_setting(&sql, "max_threads", threads);
        for (name, value) in [("input_format_parquet_max_block_size", block), ("input_format_parquet_prefer_block_bytes", prefer),
            ("input_format_parquet_memory_high_watermark", watermark)] {
            if value > 0 { sql = super::lower_setting(&sql, name, value); }
        }
        sql
    };
    let variants: Vec<(String, Box<dyn Fn(String) -> String>)> = vec![
        ("threads8".into(), Box::new(|sql| sql)),
        ("threads4".into(), Box::new(reader(4, 0, 0, 0))),
        ("bounded2".into(), Box::new(|sql: String| super::bounded_reader_sql(&sql, 2))),
        ("bounded4".into(), Box::new(|sql: String| super::bounded_reader_sql(&sql, 4))),
        ("t4-prefer1M-wm64".into(), Box::new(reader(4, 0, MIB, 64 * MIB))),
        ("t4-prefer4M-wm64".into(), Box::new(reader(4, 0, 4 * MIB, 64 * MIB))),
        ("t4-block8k-prefer4M-wm64".into(), Box::new(reader(4, 8192, 4 * MIB, 64 * MIB))),
        ("t4-block8k-prefer2M-wm32".into(), Box::new(reader(4, 8192, 2 * MIB, 32 * MIB))),
        ("t4-block8k-wm64".into(), Box::new(reader(4, 8192, 0, 64 * MIB))),
    ];
    for (name, variant) in &variants {
        let mut line = format!("{name}:");
        for cap in [64, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048] {
            let sql = variant(hash_stats_sql(8, cap * MIB));
            let started = std::time::Instant::now();
            let result = crate::query_timing::measure("probe", async {
                Ok::<_, ()>(executor.execute(plan(sql, &source)).await)
            })
            .await
            .unwrap();
            let ok = match &result {
                Ok(output) => {
                    assert!(String::from_utf8_lossy(&output.data).contains("count"));
                    "ok"
                }
                Err(error) if super::super::memory_budget::is_memory_limit_error(&error.to_string()) => "MEM",
                Err(error) => panic!("{name} {cap}: {error}"),
            };
            line.push_str(&format!(" {cap}M={ok}({:.1}s)", started.elapsed().as_secs_f64()));
            if ok == "ok" {
                break;
            }
        }
        // Wall time with memory out of the way (best of two).
        let mut best = f64::MAX;
        for _ in 0..2 {
            let started = std::time::Instant::now();
            crate::query_timing::measure("probe", async { Ok::<_, ()>(executor.execute(plan(variant(hash_stats_sql(8, 2048 * MIB)), &source)).await.unwrap()) }).await.unwrap();
            best = best.min(started.elapsed().as_secs_f64());
        }
        eprintln!("{line}  | uncapped best {best:.2}s");
    }
}

fn pool(runtime: &NativeChdb, lanes: usize, name: &str) -> NativeExecutor {
    // The 4 GiB query role's chDB total (75%).
    NativeExecutor::start_with_server_memory_limit(runtime.clone(), lanes, name, ExecutorMode::ReadOnly, Some(3 << 30)).unwrap()
}

async fn timed<T>(work: impl std::future::Future<Output = T>) -> T {
    crate::query_timing::measure("nan3393", async { Ok::<_, ()>(work.await) }).await.unwrap()
}

/// The live row shape of the same search (`<hash> | head 100`).
fn hash_rows_sql(threads: u64, memory_bytes: u64) -> String {
    format!(
        "SELECT time, \"metadata.uid\", raw_data FROM (SELECT `metadata`.`uid` AS `metadata.uid`, `message` AS `message`, \
         `raw_data` AS `raw_data`, `time` AS `time` FROM file({{source:String}}, Parquet, {{schema:String}})) \
         WHERE (positionCaseInsensitive(message, '{NEEDLE}') > 0 AND hasAllTokens(lower(message), '{NEEDLE}')) \
         OR (positionCaseInsensitive(raw_data, '{NEEDLE}') > 0 AND hasAllTokens(lower(raw_data), '{NEEDLE}')) \
         ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 100 \
         SETTINGS max_threads={threads}, max_execution_time=120, max_memory_usage={memory_bytes}, \
         max_bytes_before_external_sort={half}, max_block_size=8192, preferred_block_size_bytes=8388608, use_query_cache=0, \
         input_format_parquet_allow_missing_columns=1, input_format_parquet_filter_push_down=1",
        half = memory_bytes / 2
    )
}

const SMALL: u64 = super::SMALL_QUERY_BYTES;

fn wide_shape() -> crate::planner::ReaderShape {
    // message + raw_data over the fixture's 96 row groups, a 7 d window.
    crate::planner::ReaderShape { wide_columns: 2, row_groups: 96, window_class: 8, columns_key: 0x3393 }
}

/// Item 2 (and the parity the bounds owe): today's small-lane statement
/// fails its 256 MiB cap; bounded, the same statement fits and returns
/// exactly the rows of an unbounded 2 GiB run, for the stats and the row
/// shape alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn wide_text_statement_fits_a_small_lane_bounded_with_identical_rows() {
    let source = source_glob(&fixture(&fixture_dir()));
    let executor = pool(&runtime(), 1, "parts");
    for (shape, sql) in [("stats", hash_stats_sql as fn(u64, u64) -> String), ("rows", hash_rows_sql)] {
        let reference = timed(executor.execute(plan(sql(8, 2048 * MIB), &source))).await.unwrap();
        let text = String::from_utf8_lossy(&reference.data).to_string();
        assert!(text.lines().count() >= 2, "{shape}: the needle rows must be found: {text}");
        let today = timed(executor.execute(plan(sql(8, SMALL), &source))).await;
        let error = today.expect_err(&format!("{shape}: 8 unbounded threads must outgrow 256 MiB (the live failure)")).to_string();
        assert!(super::super::memory_budget::is_memory_limit_error(&error), "{shape}: {error}");
        let bounded = super::bounded_reader_sql(&super::cap_threads(&sql(8, SMALL), super::INTERACTIVE_MAX_THREADS), super::BOUNDED_READER_THREADS);
        let fitted = timed(executor.execute(plan(bounded, &source))).await.unwrap();
        assert_eq!(fitted.data, reference.data, "{shape}: bounded rows differ");
        // Half a small lane is enough: the bound is not a near miss.
        let half = super::bounded_reader_sql(&sql(8, SMALL / 2), super::BOUNDED_READER_THREADS);
        assert_eq!(timed(executor.execute(plan(half, &source))).await.unwrap().data, reference.data, "{shape}");
    }
}

/// Items 1 and 3 through the router: a wide-text statement with its reader
/// shape runs once, on a small lane, with no failed attempt; the same
/// statement without a shape (what the old router saw) fails small, reruns
/// large, and is then remembered, so its next run never retries small.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn router_runs_wide_text_once_on_a_small_lane_and_remembers_escalations() {
    let source = source_glob(&fixture(&fixture_dir()));
    let runtime = runtime();
    let small = pool(&runtime, 6, "parts");
    let large = super::LargeLane::new(pool(&runtime, 2, "parts-large"), 3 * 512 * MIB);
    let memo = super::LaneMemo::default();
    let reference = timed(small.execute(plan(hash_stats_sql(8, 2048 * MIB), &source))).await.unwrap();
    let mut shaped = plan(hash_stats_sql(8, SMALL), &source);
    shaped.query_sha256 = "a".repeat(64);
    shaped.reader = wide_shape();
    for round in 0..2 {
        let output = timed(super::run_sized(&small, Some(&large), &memo, shaped.clone())).await.unwrap();
        assert_eq!(output.data, reference.data, "round {round}");
    }
    assert_eq!((small.status().failed, small.status().completed), (0, 3), "no failed small attempt");
    assert_eq!(large.executor().status().completed, 0, "nothing reran on the large lane");
    assert_eq!(memo.len(), 0);

    // The old router's view: no reader shape.
    let mut blind = shaped.clone();
    blind.reader = crate::planner::ReaderShape { wide_columns: 0, ..wide_shape() };
    let output = timed(super::run_sized(&small, Some(&large), &memo, blind.clone())).await.unwrap();
    assert_eq!(output.data, reference.data);
    assert_eq!(small.status().failed, 1, "unbounded, the statement fails its small lane");
    assert_eq!(large.executor().status().completed, 1);
    assert_eq!(memo.needed(&super::LaneMemo::key(&blind).unwrap()), super::LaneClass::Large);
    for _ in 0..2 {
        let output = timed(super::run_sized(&small, Some(&large), &memo, blind.clone())).await.unwrap();
        assert_eq!(output.data, reference.data);
    }
    assert_eq!(small.status().failed, 1, "a remembered statement never retries small");
    assert_eq!(large.executor().status().completed, 3);
}

/// Item 5: the large lane runs two statements at once at half its memory;
/// one that outgrows half takes the whole lane (and is remembered).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn two_wide_large_lane_overlaps_and_escalates_to_the_whole_lane() {
    let runtime = runtime();
    let small = pool(&runtime, 6, "parts");
    let large = super::LargeLane::new(pool(&runtime, 2, "parts-large"), 3 * 512 * MIB);
    assert_eq!((large.cap_bytes(super::LaneClass::Large), large.cap_bytes(super::LaneClass::LargeFull)), (768 * MIB, 1536 * MIB));
    let memo = super::LaneMemo::default();
    let heavy = |sql: &str| {
        let mut plan = plan(format!("{sql} SETTINGS max_threads=8, max_memory_usage={SMALL}, max_execution_time=30"), "");
        plan.params.clear();
        plan.budget.estimated_scan_bytes = super::super::engine::LARGE_SCAN_BYTES + 1;
        plan
    };
    // Two 7 d scans from two users: they overlap instead of queueing.
    let started = std::time::Instant::now();
    let (a, b) = tokio::join!(
        timed(super::run_sized(&small, Some(&large), &memo, heavy("SELECT sleep(2) AS a"))),
        timed(super::run_sized(&small, Some(&large), &memo, heavy("SELECT sleep(2) AS b"))),
    );
    a.unwrap();
    b.unwrap();
    let overlapped = started.elapsed().as_secs_f64();
    assert!(overlapped < 3.5, "two large statements serialized: {overlapped:.2} s");
    assert_eq!(small.status().completed, 0);

    // One 1 GiB allocation (120M UInt64): over half the lane (768 MiB),
    // within all of it.
    let mut hog = heavy("SELECT length(range(toUInt64(120000000))) AS n");
    hog.sql = hog.sql.replace("max_threads=8", "max_threads=1");
    hog.query_sha256 = "b".repeat(64);
    let output = timed(super::run_sized(&small, Some(&large), &memo, hog.clone())).await.unwrap();
    assert_eq!(output.data, b"{\"n\":120000000}\n");
    assert_eq!(large.executor().status().failed, 1, "half the lane refuses it first");
    assert_eq!(memo.needed(&super::LaneMemo::key(&hog).unwrap()), super::LaneClass::LargeFull);
    // Remembered: straight to the whole lane, which waits for both permits.
    let (whole, other) = tokio::join!(
        timed(super::run_sized(&small, Some(&large), &memo, hog.clone())),
        timed(super::run_sized(&small, Some(&large), &memo, heavy("SELECT sleep(1) AS c"))),
    );
    assert_eq!(whole.unwrap().data, b"{\"n\":120000000}\n");
    other.unwrap();
    assert_eq!(large.executor().status().failed, 1, "no second refusal");
}

/// Item 6: every attempt carries its own native time, so a small attempt
/// that failed before its large rerun is visible in the debug evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn debug_evidence_times_each_statement_attempt() {
    let source = source_glob(&fixture(&fixture_dir()));
    let runtime = runtime();
    let small = pool(&runtime, 6, "parts");
    let large = super::LargeLane::new(pool(&runtime, 2, "parts-large"), 3 * 512 * MIB);
    let mut blind = plan(hash_stats_sql(8, SMALL), &source);
    blind.reader = crate::planner::ReaderShape { wide_columns: 0, ..wide_shape() };
    let answer = super::super::debug::collect(timed(async {
        super::run_sized(&small, Some(&large), &super::LaneMemo::default(), blind).await.unwrap();
        Ok::<_, ()>(serde_json::json!({"planner": {}}))
    }))
    .await
    .unwrap();
    let statements = answer["planner"]["native_debug"]["statements"].as_array().unwrap().clone();
    assert_eq!(statements.len(), 2, "{statements:?}");
    let (failed, rerun) = (&statements[0], &statements[1]);
    assert_eq!((failed["completed"].clone(), failed["error"].clone(), failed["lane_class"].clone()),
        (serde_json::json!(false), serde_json::json!("memory_limit"), serde_json::json!("small")));
    assert_eq!((rerun["completed"].clone(), rerun["lane_class"].clone()), (serde_json::json!(true), serde_json::json!("large")));
    for statement in [failed, rerun] {
        assert!(statement["native_ms"].as_f64().unwrap() > 0.0, "{statement}");
        assert!(statement["statement_ms"].as_f64().unwrap() >= statement["native_ms"].as_f64().unwrap(), "{statement}");
    }
    assert!(rerun["native_fetch_ms"].as_f64().unwrap() > 0.0, "{rerun}");
    // Item 4: the planner's 8 threads run as 4 on every interactive lane.
    let threads = |statement: &serde_json::Value| statement["native_settings"]["effective"].as_array().unwrap().iter()
        .find(|setting| setting["name"] == "max_threads").map(|setting| setting["value"].clone()).unwrap();
    assert_eq!((threads(failed), threads(rerun)), (serde_json::json!("4"), serde_json::json!("4")));
    eprintln!("failed small attempt: native {} ms; large rerun: native {} ms (fetch {} ms)",
        failed["native_ms"], rerun["native_ms"], rerun["native_fetch_ms"]);
}

/// Kill switch: with `NANO_LAKE_LANE_ROUTING_V2=0` the router is NAN-3077's.
/// A wide-text statement v2 would bound on a small lane runs unbounded at
/// the planner's 8 threads, fails its small lane, reruns once on the one
/// large connection with all 1.5 GiB, and nothing is remembered. Roles
/// without size classes (no large lane) keep their threads on or off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn routing_v2_off_is_the_nan3077_router() {
    let source = source_glob(&fixture(&fixture_dir()));
    let runtime = runtime();
    let small = pool(&runtime, 6, "parts");
    let large = super::LargeLane::with_routing(pool(&runtime, 1, "parts-large"), 3 * 512 * MIB, false);
    assert!(!large.routing_v2());
    assert_eq!((large.width(), large.cap_bytes(super::LaneClass::Large)), (1, 1536 * MIB));
    let memo = super::LaneMemo::default();
    let mut shaped = plan(hash_stats_sql(8, SMALL), &source);
    shaped.query_sha256 = "c".repeat(64);
    shaped.reader = wide_shape();
    assert!(super::needs_bounded_reader(&shaped.reader, super::INTERACTIVE_MAX_THREADS), "v2 would bound this statement");
    let setting = |statement: &serde_json::Value, name: &str| statement["native_settings"]["effective"].as_array().unwrap().iter()
        .find(|setting| setting["name"] == name).map(|setting| setting["value"].clone()).unwrap();
    let answer = super::super::debug::collect(timed(async {
        super::run_sized(&small, Some(&large), &memo, shaped.clone()).await.unwrap();
        Ok::<_, ()>(serde_json::json!({"planner": {}}))
    }))
    .await
    .unwrap();
    let statements = answer["planner"]["native_debug"]["statements"].as_array().unwrap().clone();
    assert_eq!(statements.len(), 2, "{statements:?}");
    let (failed, rerun) = (&statements[0], &statements[1]);
    assert_eq!((failed["error"].clone(), failed["lane_class"].clone(), failed["bounded_reader"].clone()),
        (serde_json::json!("memory_limit"), serde_json::json!("small"), serde_json::json!(false)));
    assert_eq!((rerun["completed"].clone(), rerun["lane"].clone()), (serde_json::json!(true), serde_json::json!("large")));
    assert_eq!((setting(failed, "max_threads"), setting(rerun, "max_threads")), (serde_json::json!("8"), serde_json::json!("8")));
    assert_eq!(setting(rerun, "max_memory_usage"), serde_json::json!((1536 * MIB).to_string()));
    assert_eq!(memo.len(), 0, "no memo with routing v2 off");
    // Not remembered: the next run fails its small lane again.
    super::run_sized(&small, Some(&large), &memo, shaped.clone()).await.unwrap();
    // Large: the debug run's settings probe + its rerun, then this rerun.
    assert_eq!((small.status().failed, large.executor().status().completed, large.executor().status().failed), (2, 3, 0));

    // No size classes (detect, product; no large lane, so no routing flag):
    // the planner's threads, never capped.
    let answer = super::super::debug::collect(timed(async {
        super::run_sized(&small, None, &memo, plan(hash_stats_sql(8, 2048 * MIB), &source)).await.unwrap();
        Ok::<_, ()>(serde_json::json!({"planner": {}}))
    }))
    .await
    .unwrap();
    let statements = answer["planner"]["native_debug"]["statements"].as_array().unwrap().clone();
    assert_eq!(statements.len(), 1, "{statements:?}");
    assert_eq!(setting(&statements[0], "max_threads"), serde_json::json!("8"));
}

/// NAN-3650: a statement the top class refuses in the read stage (wide
/// uncompressed text, 4 threads, default Parquet prefetch) finishes on the
/// degraded rung (one thread, bounded reader, spill at half the cap) with
/// the same rows, on a one-wide lane (Small -> Large -> Degraded), and is
/// remembered so the next run goes straight there. Calibrated against
/// libchdb 26.7.2 with a 24 MiB cap: the 4-thread read is refused in the
/// read stage; the degraded settings fit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn top_class_refusal_finishes_on_the_degraded_rung() {
    use arrow_array::{RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    const ROWS: usize = 32_000;
    const CAP: u64 = 24 * MIB;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wide.parquet");
    {
        let schema = Arc::new(Schema::new(vec![Field::new("user", DataType::Utf8, false), Field::new("raw", DataType::Utf8, false)]));
        let props = parquet::file::properties::WriterProperties::builder()
            .set_compression(parquet::basic::Compression::UNCOMPRESSED)
            .set_max_row_group_row_count(Some(4_000))
            .build();
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema.clone(), Some(props)).unwrap();
        for chunk in (0..ROWS).collect::<Vec<_>>().chunks(4_000) {
            let users = StringArray::from_iter_values(chunk.iter().map(|i| format!("user{}", i % 50)));
            let raws = StringArray::from_iter_values(chunk.iter().map(|i| format!("{i:020}").repeat(64)));
            writer.write(&RecordBatch::try_new(schema.clone(), vec![Arc::new(users), Arc::new(raws)]).unwrap()).unwrap();
        }
        writer.close().unwrap();
    }
    let sql = format!(
        "SELECT count() AS users, sum(c) AS events FROM (SELECT user, count() AS c FROM file({{source:String}}, Parquet, 'user String, raw String') \
         WHERE raw != '' GROUP BY user) SETTINGS max_threads=4, max_execution_time=60, max_memory_usage={CAP}, \
         max_bytes_before_external_sort={half}, max_bytes_before_external_group_by={half}, \
         max_temporary_data_on_disk_size_for_query={disk}, max_block_size=8192, preferred_block_size_bytes=8388608",
        half = CAP / 2, disk = CAP * 4,
    );
    let mut statement = plan(sql, path.to_str().unwrap());
    statement.params.retain(|(name, _)| name == "source");
    statement.query_sha256 = "d".repeat(64);
    let runtime = runtime();
    let small = pool(&runtime, 1, "parts");
    let large = super::LargeLane::new(pool(&runtime, 1, "parts-large"), CAP);
    assert_eq!(large.width(), 1);
    // The top class alone refuses it (the failure being fixed).
    let refused = timed(super::super::engine::run_on_routed(large.executor(), super::super::engine::with_memory_cap(statement.clone(), CAP),
        super::Route { class: super::LaneClass::Large, bounded: false, gate_wait_ms: 0.0 })).await.unwrap_err().to_string();
    assert!(super::super::memory_budget::is_memory_limit_error(&refused), "top class must refuse: {refused}");
    let memo = super::LaneMemo::default();
    let output = timed(super::run_sized(&small, Some(&large), &memo, statement.clone())).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&output.data).trim(), format!("{{\"users\":50,\"events\":{ROWS}}}"));
    assert_eq!(small.status().failed, 1, "small refuses first");
    assert_eq!((large.executor().status().failed, large.executor().status().completed), (2, 1), "large refuses, degraded finishes");
    assert_eq!(memo.needed(&super::LaneMemo::key(&statement).unwrap()), super::LaneClass::Degraded);
    // Remembered: straight to the degraded rung, no refusals.
    let again = timed(super::run_sized(&small, Some(&large), &memo, statement)).await.unwrap();
    assert_eq!(again.data, output.data);
    assert_eq!((small.status().failed, large.executor().status().failed, large.executor().status().completed), (1, 2, 2));
}
