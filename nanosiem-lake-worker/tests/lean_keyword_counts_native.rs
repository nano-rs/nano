// SPDX-License-Identifier: AGPL-3.0-or-later

//! v3 token counts answer single-keyword histograms exactly.
//!
//! The same rows are ingested twice through `ingest[T]` into signed parts:
//! once with v2 token indexes (the histogram is a full scan) and once with v3
//! (row groups inside the window are answered from per-minute token counts,
//! the rest is scanned). Every histogram must be identical, row for row, for
//! common and rare tokens, tokens that only appear next to non-ASCII bytes or
//! underscores, repeated tokens, tokens split across `message` and
//! `raw_data`, NULL columns, every bucket span, and windows that cut through
//! a part. The counts must actually serve the common-token cases.
//!
//! Run: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER,
//! `cargo test -p nanosiem-lake-worker --test lean_keyword_counts_native -- --ignored --nocapture`

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, TenantKeySet};
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const TENANT: &str = "0a8f1d3c-7b2e-4f6a-9c1d-5e4b3a2f1e00";
/// Rows, 5 ms apart (~6 minutes): more than one 65,536-row group, so a
/// window can take one group from the counts and scan the other.
const ROWS: usize = 70_000;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-test-0001", SigningKey::from_bytes(&[13; 32])).unwrap()
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).with_batch_size(1_024).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// Body text of row `i` (adversarial for the ClickHouse tokenizer).
fn raw(i: usize) -> String {
    let mut text = format!("EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE pid={i}");
    if i % 3 == 0 {
        text.push_str(" svchost.exe -k netsvcs svchost");
    }
    if i % 5 == 0 {
        // `abc` is a token here only when not glued to non-ASCII bytes.
        text.push_str(" Überabc abcü ABC_def");
    }
    if i % 7 == 0 {
        text.push_str(" über ÜBER token_under");
    }
    if i % 11 == 0 {
        text.push_str(" rundll32,Control_RunDLL");
    }
    if i % 13 == 0 { text.push_str(" caſe Kase"); }
    if i % 97 == 0 {
        text.push_str(" lsass mimikatz");
    }
    text
}

fn message(i: usize) -> Option<String> {
    match i % 4 {
        0 => None,
        1 => Some(format!("Process create {i}")),
        // The token only in `message` for these rows.
        2 => Some("cmd /c whoami & netstat".to_string()),
        _ => Some("PowerShell ran; POWERSHELL again".to_string()),
    }
}

fn row(i: usize, time: &str) -> Value {
    let mut row = json!({
        "activity_id": 1, "activity_name": "Launch", "category_uid": 1, "category_name": "System Activity",
        "class_uid": 1007, "class_name": "Process Activity", "type_uid": 100701,
        "severity": "Informational", "severity_id": 1, "status": "Success", "status_id": 1,
        "time": time,
        "raw_data": raw(i),
        "raw_data_size": raw(i).len(),
        "metadata": {"uid": format!("uid-{i:06}"), "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "actor": {"process": {"name": "explorer.exe", "pid": 4}},
        "process": {"name": "powershell.exe", "pid": i},
        "device": {"hostname": format!("ws-{:03}.corp.local", i % 50), "type_id": 2},
    });
    if let Some(message) = message(i) {
        row["message"] = json!(message);
    }
    row
}

fn notice(key: &str, at_ms: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: at_ms,
    }
}

async fn engine_over(root: &Path, rows: &[Value], counts: bool, trigrams: bool, now: chrono::DateTime<chrono::Utc>) -> PartQueryEngine {
    engine_over_layout(root, rows, counts, trigrams, now, false).await
}

async fn engine_over_layout(root: &Path, rows: &[Value], counts: bool, trigrams: bool, now: chrono::DateTime<chrono::Utc>, merged: bool) -> PartQueryEngine {
    engine_over_parts(root, rows, counts, trigrams, now, merged, if merged { 2 } else { 1 }).await
}

/// NAN-4304: a whole-minute fixture start whose next 15 minutes lie inside
/// ONE event hour (`:10` of the previous hour). Parts split by event hour,
/// so a base 10 minutes before `now` put a fixture across an hour boundary
/// whenever the test ran a few minutes past the hour, and a "one part per
/// chunk" fixture published an extra part.
fn fixture_base(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(now.timestamp() / 3600 * 3600 - 3000, 0).unwrap()
}

/// `parts` bronze files, each flushed into its own signed part (merged into
/// one minute part when `merged`).
async fn engine_over_parts(root: &Path, rows: &[Value], counts: bool, trigrams: bool, now: chrono::DateTime<chrono::Utc>, merged: bool, part_count: usize) -> PartQueryEngine {
    // NAN-4164: a caller that set NANO_LAKE_PAIR_INDEX=1 gets v5 parts;
    // otherwise the (default-on) pair writer is switched off for this ingest.
    let pairs = std::env::var(nanosiem_lake_worker::parts::sidecar::PAIR_ENABLE_ENV).as_deref() == Ok("1");
    if !pairs {
        std::env::set_var(nanosiem_lake_worker::parts::sidecar::PAIR_ENABLE_ENV, "0");
    }
    // NAN-4217: likewise NANO_LAKE_IP_TOKEN_INDEX=1 (with pairs) gets v6.
    let addresses = pairs && nanosiem_lake_worker::parts::sidecar::ip_tokens_enabled();
    if trigrams { std::env::set_var("NANO_LAKE_TRIGRAM_INDEX", "1"); } else { std::env::remove_var("NANO_LAKE_TRIGRAM_INDEX"); }
    nanosiem_lake_worker::parts::block_index::set_enabled(true);
    nanosiem_lake_worker::parts::token_counts::set_enabled(counts);
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    for (index, chunk) in rows.chunks(rows.len().div_ceil(part_count)).enumerate() {
        let key = format!("bronze/{index:04}.parquet");
        write_bronze(&sources_dir.join(&key), chunk);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).unwrap();
        let at = now_ms + index as i64 * 11_000;
        spool.deliver(&notice(&key, at)).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    if merged {
        ingestor.tick(now_ms + 120_000).await.expect("minute merge completes");
        let live = load_log(&parts, TENANT).await.unwrap();
        assert_eq!(live.parts().count(), 1);
        assert_eq!(live.parts().next().unwrap().level, nanosiem_lake_worker::parts::levels::Level::Minute);
    }
    assert!(load_log(&parts, TENANT).await.unwrap().parts().next().is_some(), "a signed part was published");
    drop(ingestor);
    std::env::remove_var("NANO_LAKE_TRIGRAM_INDEX");
    std::env::remove_var(nanosiem_lake_worker::parts::sidecar::PAIR_ENABLE_ENV);
    std::env::remove_var(nanosiem_lake_worker::parts::sidecar::IP_TOKEN_ENABLE_ENV);
    nanosiem_lake_worker::parts::block_index::set_enabled(false);
    nanosiem_lake_worker::parts::token_counts::set_enabled(false);

    let mut magics = BTreeSet::new();
    for entry in walk(&root.join("parts")) {
        if entry.extension().is_some_and(|e| e == "nti") {
            magics.insert(std::fs::read(&entry).unwrap()[..8].to_vec());
        }
    }
    assert_eq!(magics, BTreeSet::from([if trigrams && addresses { b"NANOTKI6".to_vec() } else if trigrams && pairs { b"NANOTKI5".to_vec() } else if trigrams { b"NANOTKI4".to_vec() } else if counts { b"NANOTKI3".to_vec() } else { b"NANOTKI2".to_vec() }]));

    let trusted: TenantKeySet = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "keyword-counts-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: root.join("query-cache"), max_bytes: 256 << 20, query_max_bytes: 256 << 20,
        fetch_concurrency: 2, fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, if counts { "counts-v3" } else { "counts-v2" }, ExecutorMode::ReadOnly).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 256 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 60, threads: 1,
    }, store, view, fetcher, executor).unwrap()
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() { out.extend(walk(&path)); } else { out.push(path); }
    }
    out
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn v3_counts_answer_histograms_exactly() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let now = chrono::Utc::now();
    // Whole-minute base, so windows can be cut on and off minute bounds.
    let base = fixture_base(now);
    let rows = (0..ROWS)
        .map(|i| row(i, &(base + chrono::Duration::milliseconds(i as i64 * 5)).to_rfc3339()))
        .collect::<Vec<_>>();
    let v2_dir = tempfile::tempdir().unwrap();
    let v3_dir = tempfile::tempdir().unwrap();
    let v2 = engine_over(v2_dir.path(), &rows, false, false, now).await;
    let v3 = engine_over(v3_dir.path(), &rows, true, false, now).await;
    let v4_dir = tempfile::tempdir().unwrap();
    let v4 = engine_over(v4_dir.path(), &rows, true, true, now).await;
    let at = |seconds: i64| (base + chrono::Duration::seconds(seconds)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let request = |query: &str, start: &str, end: &str| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: start.into(), end: end.into(),
        limit: 100_000, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    // Group 1 holds rows 0..65,536 (0 to ~327.7 s), group 2 the rest (to
    // ~350 s). A window that cuts a group scans it and counts the other.
    let windows = [
        (at(-600), at(900)),
        (at(-600), at(340)),
        (at(100), at(900)),
        (at(0), at(900)),
        (at(100), at(340)),
    ];
    let tokens = [
        "powershell", "svchost", "exe", "abc", "def", "under", "token", "rundll32", "control",
        "lsass", "mimikatz", "whoami", "cmd", "process", "create", "1", "12", "eventid", "absent",
        "über", "ÜBER", "PowerShell",
    ];
    let spans = ["1m", "5m", "10m", "1h", "30s"];
    let (mut served, mut compared) = (0, 0);
    for (start, end) in &windows {
        for token in tokens {
            for span in spans {
                let query = format!("{token} | timechart span={span} count() as count");
                let a = v2.broad_npl(&request(&query, start, end)).await.unwrap_or_else(|e| panic!("v2 {query}: {e:#}"));
                let b = v3.broad_npl(&request(&query, start, end)).await.unwrap_or_else(|e| panic!("v3 {query}: {e:#}"));
                assert_eq!(a["result"]["rows"], b["result"]["rows"], "{query} over [{start}, {end}]: v3 counts differ from the scan\nv3 planner {}", b["planner"]);
                assert_eq!(a["result"]["page_has_more"], b["result"]["page_has_more"], "{query}");
                let c = v4.broad_npl(&request(&query, start, end)).await.unwrap();
                assert_eq!(a["result"]["rows"], c["result"]["rows"], "v4 {query}");
                compared += 1;
                if b["planner"]["count_groups"].as_u64().unwrap_or(0) > 0 {
                    served += 1;
                }
            }
        }
        // Totals too: the sum is what the UI shows.
        let query = "powershell | timechart span=5m count() as count";
        let b = v3.broad_npl(&request(query, start, end)).await.unwrap();
        let total = b["result"]["rows"].as_array().unwrap().iter().map(|r| r["count"].as_u64().unwrap()).sum::<u64>();
        eprintln!("[{start}, {end}] powershell total {total}, planner {}", b["planner"]);
    }
    eprintln!("{served} of {compared} histograms used the counts");
    // Native SQL remains the final recheck. Compare rows (including masks)
    // and exact counts with the legacy path for 120 deterministic AND chains.
    let terms = ["raw_data=\"*dll32*\"", "raw_data=/dll32/", "raw_data=/case/", "raw_data=/kase/", "*shell*", "raw_data=\"*svch*\"", "raw_data=\"*abc*\"", "powershell", "mimikatz", "raw_data=\"*absent*\""];
    let mut seed = 0x3077_u64;
    for _ in 0..120 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let left = terms[(seed >> 32) as usize % terms.len()];
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let right = terms[(seed >> 32) as usize % terms.len()];
        for tail in [" | head 20", " | stats count"] {
            let query = format!("{left} AND {right}{tail}");
            let req = request(&query, &at(-600), &at(900));
            let a = v2.broad_npl(&req).await.unwrap();
            let b = v4.broad_npl(&req).await.unwrap();
            assert_eq!(a["result"]["rows"], b["result"]["rows"], "{query}");
            assert_eq!(a["result"]["page_has_more"], b["result"]["page_has_more"], "{query}");
        }
    }

    // Four windows hold a whole group, so every common token (>= 16 rows a
    // group) is served in them for every minute span.
    assert!(served >= 4 * 4 * 8, "counts served only {served} histograms");

    // NAN-4164: the scalar `<kw> | stats count` (the search total and the
    // distributed stats path) is answered from the same counts, exactly.
    let mut scalar_served = 0;
    for (start, end) in &windows {
        for token in tokens {
            for query in [format!("{token} | stats count"), format!("{token} | stats count as n")] {
                let a = v2.broad_npl(&request(&query, start, end)).await.unwrap_or_else(|e| panic!("v2 {query}: {e:#}"));
                let b = v3.broad_npl(&request(&query, start, end)).await.unwrap_or_else(|e| panic!("v3 {query}: {e:#}"));
                let c = v4.broad_npl(&request(&query, start, end)).await.unwrap();
                assert_eq!(a["result"]["rows"], b["result"]["rows"], "{query} over [{start}, {end}]: v3 counts differ from the scan\nv3 planner {}", b["planner"]);
                assert_eq!(a["result"]["rows"], c["result"]["rows"], "v4 {query}");
                assert_eq!(a["planner"]["count_groups"].as_u64().unwrap_or(0), 0, "v2 has no counts: {query}");
                if b["planner"]["count_groups"].as_u64().unwrap_or(0) > 0 {
                    scalar_served += 1;
                }
            }
        }
    }
    eprintln!("{scalar_served} scalar counts used the counts");
    assert!(scalar_served >= 4 * 4 * 2, "counts served only {scalar_served} scalar counts");

    // NAN-4164: with the per-part result cache on (as live cells run), the
    // count and histogram shapes go through the per-part partial path, which
    // must take the counts too, and stay exact.
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let mut partial_served = 0;
    for (start, end) in &windows {
        for query in ["powershell | stats count", "svchost | stats count as n", "absent | stats count", "powershell | timechart span=1m count() as count", "exe | timechart span=5m count() as count"] {
            let truth = v2.broad_npl(&request(query, start, end)).await.unwrap();
            for round in 0..2 {
                let mut cached = request(query, start, end);
                cached.use_cache = true;
                // The partial path serves pages of at most 4,096 rows.
                cached.limit = 1_000;
                let b = v3.broad_npl(&cached).await.unwrap_or_else(|e| panic!("v3 cached {query}: {e:#}"));
                assert_eq!(truth["result"]["rows"], b["result"]["rows"], "{query} over [{start}, {end}] round {round}: partials differ\nplanner {}", b["planner"]);
                // Round 1 may be answered by the whole-result cache.
                if round > 0 { continue; }
                let kind = b["planner"]["kind"].as_str().unwrap_or_default();
                assert!(kind == "stats_count_partial" || kind == "histogram", "{query}: partial path expected, got {}", b["planner"]);
                assert_eq!(b["planner"]["keyword_counts"]["applies"], json!(true), "{query}: {}", b["planner"]);
                if b["planner"]["keyword_counts"]["groups"].as_u64().unwrap_or(0) > 0 {
                    partial_served += 1;
                }
            }
        }
    }
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    // Partials are cached per part over the window clamped to the part, so
    // the first window computes them (from the counts) and windows that
    // still cover the same parts reuse them; at least the four common
    // shapes of the first window must have counted.
    assert!(partial_served >= 4, "partials used the counts only {partial_served} times");

    // Other shapes never take the count path.
    for query in ["powershell | stats count by process.name", "powershell svchost | stats count", "powershell svchost | timechart span=1m count() as count", "powershell | timechart span=1m count() as count by process.name"] {
        let b = v3.broad_npl(&request(query, &at(-600), &at(900))).await.unwrap();
        assert_eq!(b["planner"]["count_groups"].as_u64().unwrap_or(0), 0, "{query}");
        let a = v2.broad_npl(&request(query, &at(-600), &at(900))).await.unwrap();
        assert_eq!(a["result"]["rows"], b["result"]["rows"], "{query}");
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned native chDB and lake compiler"]
async fn merged_output_preserves_120_and_chains_rows_masks_and_exact_counts() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-25T00:15:00Z").unwrap().with_timezone(&chrono::Utc);
    let base = now - chrono::Duration::minutes(10);
    let rows = (0..6_000).map(|i| row(i, &(base + chrono::Duration::milliseconds(i as i64 * 5)).to_rfc3339())).collect::<Vec<_>>();
    let original_dir = tempfile::tempdir().unwrap();
    let merged_dir = tempfile::tempdir().unwrap();
    let original = engine_over_layout(original_dir.path(), &rows, true, true, now, false).await;
    let merged = engine_over_layout(merged_dir.path(), &rows, true, true, now, true).await;
    let terms = ["powershell", "mimikatz", "raw_data=\"*dll32*\"", "raw_data=/case/", "raw_data=/kase/", "*shell*", "raw_data=\"*svch*\"", "raw_data=\"*absent*\""];
    let mut seed = 0x3077_u64;
    for _ in 0..120 {
        let mut chain = Vec::new();
        for _ in 0..3 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            chain.push(terms[(seed >> 32) as usize % terms.len()]);
            for tail in [" | head 20", " | stats count"] {
                let query = format!("{}{tail}", chain.join(" AND "));
                let request = BroadNplRequest {
                    request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
                    dataset: "logs".into(), query: query.clone(),
                    start: (base - chrono::Duration::seconds(1)).to_rfc3339(), end: now.to_rfc3339(),
                    limit: 100_000, offset: 0, table_view: false, use_cache: false,
                    cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
                    clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
                };
                let a = original.broad_npl(&request).await.unwrap();
                let b = merged.broad_npl(&request).await.unwrap();
                assert_eq!(a["result"]["rows"], b["result"]["rows"], "{query}");
                assert_eq!(a["result"]["page_has_more"], b["result"]["page_has_more"], "{query}");
            }
        }
    }
}

/// Signed-parts end-to-end page/companion/export regression for NAN-3077.
#[tokio::test]
#[ignore = "requires pinned native chDB and lake compiler"]
async fn stats_topn_pages_preserve_totals_companions_and_export_sql() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-25T00:15:00Z").unwrap().with_timezone(&chrono::Utc);
    let base = now - chrono::Duration::minutes(10);
    let events = (0..6_000).map(|i| row(i, &(base + chrono::Duration::milliseconds(i as i64 * 5)).to_rfc3339())).collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_over(dir.path(), &events, true, false, now).await;
    let base_query = "metadata.log_source=windows_sysmon | stats count by process.pid, device.hostname";
    let mut request = BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: base_query.into(),
        start: (base - chrono::Duration::seconds(1)).to_rfc3339(), end: now.to_rfc3339(),
        limit: 10_000, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    for suffix in ["", " | sort -count", " | sort -count | head 120"] {
        request.query = format!("{base_query}{suffix}");
        request.offset = 0;
        request.limit = 10_000;
        let full = Box::pin(engine.broad_npl(&request)).await.unwrap();
        let expected = full["result"]["rows"].as_array().unwrap();
        let total = if suffix.ends_with("head 120") { 120 } else { 6_000 };
        assert_eq!(expected.len(), total);
        for offset in [0, 50, 100, 6_001] {
            request.offset = offset;
            request.limit = 50;
            let (page, companion) = tokio::join!(Box::pin(engine.broad_npl(&request)), Box::pin(async {
                let mut histogram = request.clone();
                histogram.query = "metadata.log_source=windows_sysmon | timechart span=1m count".into();
                histogram.offset = 0;
                histogram.limit = 100;
                Box::pin(engine.broad_npl(&histogram)).await
            }));
            let page = page.unwrap();
            let page_rows = page["result"]["rows"].as_array().unwrap();
            if suffix.is_empty() && offset == 0 {
                eprintln!("stats_topn signed fixture: {}", json!({
                    "groups": total,
                    "full": {"rows": expected.len(), "engine_s": full["result"]["engine_seconds"], "worker_wall_s": full["wall_seconds"]},
                    "page": {"rows": page_rows.len(), "engine_s": page["result"]["engine_seconds"], "worker_wall_s": page["wall_seconds"]}
                }));
            }
            assert_eq!(page["result"]["group_total"].as_u64(), Some(total as u64));
            assert_eq!(page_rows, &expected.iter().skip(offset).take(50).cloned().collect::<Vec<_>>());
            assert_eq!(page["result"]["page_has_more"], json!(offset + page_rows.len() < total));
            assert!(page_rows.iter().all(|row| row.get("__nano_stats_total").is_none()));
            let companion = companion.unwrap();
            let events = companion["result"]["rows"].as_array().unwrap().iter()
                .map(|row| row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|s| s.parse().ok())).unwrap())
                .sum::<u64>();
            assert_eq!(events, 6_000);
        }
    }
    request.query = base_query.into();
    request.limit = 50;
    request.offset = 0;
    request.use_cache = true;
    let first = Box::pin(engine.broad_npl(&request)).await.unwrap();
    let cached = Box::pin(engine.broad_npl(&request)).await.unwrap();
    assert_eq!(first["result"]["group_total"], cached["result"]["group_total"]);
    assert_eq!(first["result"]["rows"], cached["result"]["rows"]);
    // Durable jobs use compile(), which deliberately has no interactive
    // metadata and retains the ordinary complete-result/export SQL contract.
    let export = engine.compile(&request, BTreeMap::new()).await.unwrap();
    assert!(!export.stats_page);
    assert!(!export.sql.contains("__nano_stats_total"));
    request.query = format!("{base_query} | where count > 10");
    assert!(Box::pin(engine.broad_npl(&request)).await.unwrap()["result"]["group_total"].is_null());
}

/// NAN-4164: body text for the term-adjacency test. Every compound needle's
/// tokens occur in most rows (in timestamps, pids, other hosts) but in order,
/// with a token boundary on each end, only where noted.
fn term_raw(i: usize) -> String {
    let mut text = format!("2026-10-01T04:20:{:02} pid={i} host 10.1.9.{}", i % 60, i % 250);
    match i % 12 {
        0 => text.push_str(" src=10.1.4.20 dst=8.8.8.8"),
        1 => text.push_str(" src=110.1.4.201"),
        2 => text.push_str(" sshd: Failed password for root"),
        3 => text.push_str(" password failed for root; failedpassword"),
        4 => text.push_str(" Computer: WS-FIN-095.corp"),
        5 => text.push_str(" Computer: ws-fin-0951 095"),
        6 => text.push_str(" Logon Audit\tFAILURE"),
        7 => text.push_str(" Failure Audit"),
        8 => text.push_str(" ip=10.1.4.20:443"),
        _ => {}
    }
    text
}

fn term_message(i: usize) -> Option<String> {
    match i % 9 {
        0 => None,
        // The needle only in `message` for these rows.
        1 => Some("sshd: FAILED   password".to_string()),
        2 => Some("peer 10.1.4.200".to_string()),
        _ => Some(format!("event {i}")),
    }
}

/// Independent truth for a needle: whitespace-normalized, ASCII
/// case-insensitive substring with a non-alphanumeric (or edge) neighbour.
fn holds_term(text: &str, needle: &str) -> bool {
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    let (text, needle) = (norm(text), norm(needle));
    let bytes = text.as_bytes();
    text.match_indices(&needle).any(|(at, _)| {
        let before = at.checked_sub(1).map(|b| bytes[b]);
        let after = bytes.get(at + needle.len()).copied();
        !before.is_some_and(|b| b.is_ascii_alphanumeric()) && !after.is_some_and(|b| b.is_ascii_alphanumeric())
    })
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn compound_keywords_match_as_terms() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let now = chrono::Utc::now();
    let base = fixture_base(now);
    let n = 6_000;
    let rows = (0..n)
        .map(|i| {
            let mut value = row(i, &(base + chrono::Duration::milliseconds(i as i64 * 50)).to_rfc3339());
            value["raw_data"] = json!(term_raw(i));
            value["raw_data_size"] = json!(term_raw(i).len());
            match term_message(i) {
                Some(message) => value["message"] = json!(message),
                None => { value.as_object_mut().unwrap().remove("message"); }
            }
            value
        })
        .collect::<Vec<_>>();
    let at = |seconds: i64| (base + chrono::Duration::seconds(seconds)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let request = |query: &str| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: at(-60), end: at(900),
        limit: 100_000, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    let count_of = |out: &Value| out["result"]["rows"][0]["n"].as_u64().or_else(|| out["result"]["rows"][0]["n"].as_str().and_then(|s| s.parse().ok()));
    // v4 (token-AND evidence only) and v5 (adjacent-pair blooms) must agree.
    for pairs in [false, true] {
        if pairs {
            std::env::set_var(nanosiem_lake_worker::parts::sidecar::PAIR_ENABLE_ENV, "1");
        }
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_over(dir.path(), &rows, true, true, now).await;
        for (needle, query_needle) in [
            ("10.1.4.20", "10.1.4.20"),
            ("failed password", "\"failed password\""),
            ("FAILED PASSWORD", "\"FAILED PASSWORD\""),
            ("ws-fin-095", "ws-fin-095"),
            ("audit failure", "\"Audit Failure\""),
            ("10.1.4.20:443", "\"10.1.4.20:443\""),
        ] {
            let expected = (0..n)
                .filter(|&i| holds_term(&term_raw(i), needle) || term_message(i).is_some_and(|m| holds_term(&m, needle)))
                .count();
            assert!(expected > 0, "{needle}: fixture must hold the term");
            let all_tokens = (0..n)
                .filter(|&i| {
                    let body = format!("{} {}", term_raw(i), term_message(i).unwrap_or_default()).to_ascii_lowercase();
                    let words = body.split(|c: char| !c.is_ascii_alphanumeric()).collect::<BTreeSet<_>>();
                    needle.to_ascii_lowercase().split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).all(|t| words.contains(t))
                })
                .count();
            assert!(all_tokens > expected, "{needle}: fixture must hold token-AND false positives ({all_tokens} vs {expected})");

            let query = format!("{query_needle} | stats count() as n");
            let out = engine.broad_npl(&request(&query)).await.unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert_eq!(count_of(&out), Some(expected as u64), "pairs={pairs} {query}: {}", out["result"]["rows"]);
            assert_eq!(out["planner"]["token_pruned_files"].as_u64(), Some(0), "pairs={pairs} {query}: a holding part is kept");

            let out = engine.broad_npl(&request(query_needle)).await.unwrap_or_else(|e| panic!("{query_needle}: {e:#}"));
            let rows = out["result"]["rows"].as_array().unwrap();
            assert_eq!(rows.len(), expected, "pairs={pairs} {query_needle}: events");
        }
        // Every piece of these needles is in the part (`4` and `20` from
        // 10.1.4.20, `99` from pids and 10.1.9.99, `fin`/`password` words),
        // but never adjacent: only the pair bloom can skip the part.
        for query_needle in ["4.20.99", "\"password fin\"", "\"root 095\""] {
            let query = format!("{query_needle} | stats count() as n");
            let out = engine.broad_npl(&request(&query)).await.unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert_eq!(count_of(&out).unwrap_or(0), 0, "pairs={pairs} {query}: {}", out["result"]["rows"]);
            let pruned = out["planner"]["token_pruned_files"].as_u64().unwrap_or(0);
            if pairs {
                assert!(pruned > 0, "{query}: v5 pairs must prune the part, planner {}", out["planner"]);
            } else {
                assert_eq!(pruned, 0, "{query}: v4 cannot prune on scattered pieces, planner {}", out["planner"]);
            }
        }
    }
}

/// NAN-4217: body text for the whole-address test. Every part holds every
/// number piece and every adjacent pair of `48.170.34.111` and `10.0.0.5`,
/// and near misses of both; only part 2 holds `48.170.34.111` itself, only
/// part 3 `10.0.0.5`, only part 1 `fe80::1`.
fn ip_raw(i: usize, part: usize) -> String {
    let mut text = format!(
        "2026-10-01T04:20:{:02} pid={i} 148.170.34.1119 48.170.34.11 34.111.0.1 170.34.9.9 48.170.1.1 \
         10.0.0.50 110.0.0.5 0.0.5.7 dst=10.1.{}.{} fe80::10 1fe80::1 fe80-1",
        i % 60, i % 7, i % 250
    );
    match (part, i % 40) {
        (2, 0) => text.push_str(" src=48.170.34.111:443"),
        (2, 1) => text.push_str(" peer [48.170.34.111]"),
        (3, 0) => text.push_str(" ip=10.0.0.5"),
        (1, 0) => text.push_str(" from FE80::1%eth0"),
        _ => {}
    }
    text
}

fn ip_message(i: usize, part: usize) -> Option<String> {
    match (part, i % 9) {
        (_, 0) => None,
        // The needle only in `message` for this row.
        (2, 4) if i % 360 == 4 => Some("login from 48.170.34.111".to_string()),
        _ => Some(format!("event {i}")),
    }
}

/// NAN-4217: bare IPs over v5 (pairs) and v6 (whole-address tokens) parts
/// ingested through `ingest[T]` and searched through the real engine. The
/// rows (and counts) are identical to an independent term truth on both;
/// v6 prunes every part that does not hold the address although each holds
/// all of its pieces and pairs, which v5 cannot.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn bare_ips_prune_on_whole_address_tokens() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let now = chrono::Utc::now();
    let base = fixture_base(now);
    const PARTS: usize = 4;
    let n = 4_000;
    let part_of = |i: usize| i * PARTS / n;
    let rows = (0..n)
        .map(|i| {
            let mut value = row(i, &(base + chrono::Duration::milliseconds(i as i64 * 50)).to_rfc3339());
            let raw = ip_raw(i, part_of(i));
            value["raw_data"] = json!(raw);
            value["raw_data_size"] = json!(raw.len());
            match ip_message(i, part_of(i)) {
                Some(message) => value["message"] = json!(message),
                None => { value.as_object_mut().unwrap().remove("message"); }
            }
            value
        })
        .collect::<Vec<_>>();
    let at = |seconds: i64| (base + chrono::Duration::seconds(seconds)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let request = |query: &str| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: at(-60), end: at(900),
        limit: 100_000, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    let count_of = |out: &Value| out["result"]["rows"][0]["n"].as_u64().or_else(|| out["result"]["rows"][0]["n"].as_str().and_then(|s| s.parse().ok()));
    let uids = |out: &Value| out["result"]["rows"].as_array().unwrap().iter()
        .map(|row| row["metadata.uid"].as_str().or_else(|| row["metadata"]["uid"].as_str()).map_or_else(|| row.to_string(), str::to_string))
        .collect::<BTreeSet<_>>();
    // (needle as typed, needle for the truth, parts that hold it)
    let needles = [
        ("48.170.34.111", "48.170.34.111", 1),
        ("\"48.170.34.111\"", "48.170.34.111", 1),
        ("10.0.0.5", "10.0.0.5", 1),
        ("fe80::1", "fe80::1", 1),
        ("FE80::1", "fe80::1", 1),
        ("48.170.34.11", "48.170.34.11", PARTS),
        ("148.170.34.111", "148.170.34.111", 0),
        ("10.0.0.6", "10.0.0.6", 0),
    ];
    let mut answers: BTreeMap<(bool, &str), BTreeSet<String>> = BTreeMap::new();
    for v6 in [false, true] {
        std::env::set_var(nanosiem_lake_worker::parts::sidecar::PAIR_ENABLE_ENV, "1");
        if v6 {
            std::env::set_var(nanosiem_lake_worker::parts::sidecar::IP_TOKEN_ENABLE_ENV, "1");
        }
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_over_parts(dir.path(), &rows, true, true, now, false, PARTS).await;
        let files = walk(&dir.path().join("parts")).iter().filter(|p| p.extension().is_some_and(|e| e == "nti")).count();
        assert_eq!(files, PARTS, "one data file per part");
        for (query_needle, needle, holding_parts) in needles {
            let expected = (0..n)
                .filter(|&i| holds_term(&ip_raw(i, part_of(i)), needle) || ip_message(i, part_of(i)).is_some_and(|m| holds_term(&m, needle)))
                .count();
            assert_eq!(expected > 0, holding_parts > 0, "{needle}: fixture");

            let query = format!("{query_needle} | stats count() as n");
            let out = engine.broad_npl(&request(&query)).await.unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert_eq!(count_of(&out).unwrap_or(0), expected as u64, "v6={v6} {query}: {}", out["result"]["rows"]);

            let out = engine.broad_npl(&request(query_needle)).await.unwrap_or_else(|e| panic!("{query_needle}: {e:#}"));
            let found = uids(&out);
            assert_eq!(found.len(), expected, "v6={v6} {query_needle}: events");
            // The progressive event path reports its token funnel in the
            // whole-window preselect evidence.
            let planner = &out["planner"];
            let pruned = planner["token_pruned_files"].as_u64()
                .or_else(|| planner["preselect"]["evidence"]["token_pruned_files"].as_u64()).unwrap_or(0) as usize;
            let fetched = out["planner"]["fetched_files"].as_u64().unwrap_or(0) as usize;
            println!("v6={v6} {query_needle}: rows={} token_pruned_files={pruned} fetched_files={fetched} of {files}", found.len());
            if v6 {
                // Every part holds the pieces (and, but for 10.0.0.6, the
                // pairs): only the whole address prunes, every part without it.
                assert_eq!((pruned, fetched), (PARTS - holding_parts, holding_parts),
                    "v6 {query_needle}: the address token must prune exactly the parts without it, planner {}", out["planner"]);
            }
            if !v6 && needle != "148.170.34.111" && needle != "10.0.0.6" {
                assert_eq!((pruned, fetched), (0, PARTS), "v5 {query_needle}: pieces and pairs are in every part, planner {}", out["planner"]);
            }
            answers.insert((v6, query_needle), found);
        }
    }
    for (query_needle, _, _) in needles {
        assert_eq!(answers[&(false, query_needle)], answers[&(true, query_needle)], "{query_needle}: v5 and v6 rows differ");
    }
}
