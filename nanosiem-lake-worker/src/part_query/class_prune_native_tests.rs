// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3188, native: `class_uid = N` file pruning over a class-clustered hour
//! part, end-to-end (real ingestor + hour merge under
//! `NANO_LAKE_COMPACTION_LAYOUT` or NAN-3437 `NANO_LAKE_CLASS_FAMILIES`, real
//! compiler, planner, chDB). The hinted
//! query must prune whole source/class files and return exactly the rows of
//! an unhinted form (`| eval c = class_uid + 0 | where c = N`), which prunes
//! nothing. Since NAN-4155 the `| where class_uid = N` form carries the same
//! class hint, so it must prune like the search form and return those rows.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::engine::class_prune_native -- --ignored --nocapture --test-threads=1
//! ```

use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::levels::Level;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, DurationRound, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "5e1f9a3c-7b2d-4c8e-9f0a-1b2c3d4e5f60";
/// Above the 8 x 8,192-row clustering floor of the `8192:67108864` layout.
const ROWS: usize = 72_000;
const BRONZE_FILES: usize = 4;
/// Three classes (shapes OCSF 1.9 admission accepts); 4001 is a third of
/// the hour and the only one queried.
const CLASSES: [i64; 3] = [1007, 3002, 4001];

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(
        "lab-signer-nan3188",
        ed25519_dalek::SigningKey::from_bytes(&[88; 32]),
    )
    .unwrap()
}

fn class(i: usize) -> i64 {
    CLASSES[i % CLASSES.len()]
}

/// Port 445 is also on authentication events, so only the SQL (not the
/// port) decides class membership.
fn port(i: usize) -> i64 {
    if i % 4 == 0 {
        445
    } else {
        443
    }
}

fn host(i: usize) -> String {
    format!("ws-{}.corp.local", i % 13)
}

fn event(i: usize, time: &str) -> Value {
    let class = class(i);
    let activity = 1 + (i % 2) as i64;
    let text = format!("class {class} activity {activity} seq {i}");
    // An incompressible payload, as real raw events are: the 8,192-row
    // layout's fixed per-group overhead (footers, blooms) must not dominate
    // a fixture this small, or the 105% storage gate keeps the baseline.
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(i.to_le_bytes()));
    let raw = format!("raw {text} {digest}{digest}{digest}{digest}");
    let mut row = json!({
        "class_uid": class, "category_uid": class / 1000, "activity_id": activity, "type_uid": class * 100 + activity,
        "severity_id": 1, "time": time, "message": text, "raw_data_size": raw.len(), "raw_data": raw,
    });
    match class {
        1007 => {
            row["process"] = json!({"pid": 4000 + i % 97, "name": format!("proc{}", i % 97),
                "file": {"name": format!("proc{}.exe", i % 97), "type_id": 1}});
            row["actor"] = json!({"process": {"pid": 600, "name": "services.exe"}});
            row["device"] = json!({"hostname": host(i), "type_id": 2});
            row["status"] = json!("Success");
        }
        3002 => {
            row["actor"] = json!({"user": {"name": format!("user{}", i % 17)}});
            row["user"] = json!({"name": format!("user{}", i % 17), "uid": "S-1-5-21-1"});
            row["src_endpoint"] =
                json!({"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": host(i)});
            row["dst_endpoint"] = json!({"ip": "192.168.1.1", "port": port(i)});
            row["status"] = json!("Failure");
            row["status_id"] = json!(2);
        }
        _ => {
            row["src_endpoint"] =
                json!({"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": host(i)});
            row["dst_endpoint"] = json!({"ip": "203.0.113.9", "port": port(i)});
            row["status"] = json!("Success");
        }
    }
    // One source holding every class: the source-only layout interleaves
    // the classes in one file; the class layout splits them.
    let source = "windows_event";
    row["metadata"] = json!({"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
        "product": {"name": source, "vendor_name": "fixture"}});
    row
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) =
        infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema))
        .build(std::io::Cursor::new(lines))
        .unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| {
                parquet::arrow::ArrowWriter::try_new(
                    std::fs::File::create(path).unwrap(),
                    batch.schema(),
                    None,
                )
                .unwrap()
            })
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

fn event_time(hour: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    hour + Duration::milliseconds(i as i64 * 49)
}

/// Ingest one hour at its own clock, then advance the clock until the
/// sealed hour is a single (class-clustered) hour part.
async fn ingest_and_seal(root: &std::path::Path, hour: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let hour_ms = hour.timestamp_millis();
    let mut ingestor = Ingestor::open(
        config,
        &parts,
        &sources,
        &spool as &dyn NoticeQueue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        hour_ms,
    )
    .await
    .expect("ingest opens");
    let per = ROWS / BRONZE_FILES;
    for n in 0..BRONZE_FILES {
        let batch = (n * per..(n + 1) * per)
            .map(|i| event(i, &event_time(hour, i).to_rfc3339()))
            .collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT)
            .expect("bronze admitted");
        let at = event_time(hour, (n + 1) * per).timestamp_millis();
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(),
                key,
                version: "1".into(),
                bytes: 0,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: at,
            })
            .unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor
            .flush_now(at + 5_000)
            .await
            .expect("ingest flushes");
    }
    let mut clock = hour_ms + 4 * 3_600_000;
    for _ in 0..600 {
        ingestor.tick(clock).await.expect("tick");
        clock += 1_000;
        let live = crate::parts::part_log::load_log(&parts, TENANT)
            .await
            .unwrap();
        if live.parts().count() == 1 && live.parts().all(|part| part.level == Level::Hour) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the hour never sealed into one hour part");
}

async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone())
        .await
        .unwrap();
    let bucket = "nan3188-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.join("cache"),
            max_bytes: 1 << 30,
            query_max_bytes: 1 << 29,
            fetch_concurrency: 4,
            fetch_deadline: std::time::Duration::from_secs(60),
        },
        TENANT,
        bucket,
        &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local(
            bucket,
            store.clone(),
            root.join("parts"),
        )),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        1,
        "parts",
        ExecutorMode::ReadOnly,
        Some(256 << 20),
    )
    .unwrap()
    .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        1,
        "parts-large",
        ExecutorMode::ReadOnly,
        Some(3 << 29),
    )
    .unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts-rw",
        ExecutorMode::ReadWrite,
        Some(3 << 29),
    )
    .unwrap();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER")
                .expect("NANO_LAKE_COMPILER")
                .into(),
            max_query_bytes: 64 << 30,
            max_memory_bytes: 256 << 20,
            max_execution_seconds: 120,
            threads: 2,
        },
        store,
        view,
        fetcher,
        small,
    )
    .unwrap()
    .with_writer(writer)
    .with_large(large, 3 << 29)
    .with_state_dir(&state)
}

fn request(query: &str, hour: DateTime<Utc>, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3188".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: (hour - Duration::hours(1)).to_rfc3339(),
        end: (hour + Duration::hours(2)).to_rfc3339(),
        limit: 100_000,
        offset: 0,
        table_view,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

/// Rows and the request's selection funnel.
async fn run(
    engine: &PartQueryEngine,
    query: &str,
    hour: DateTime<Utc>,
    table_view: bool,
) -> (Vec<Value>, crate::query_timing::Funnel) {
    engine.clear_locator_cache();
    let request = request(query, hour, table_view);
    crate::query_timing::measure("nan3188", async {
        let answer = engine.broad_npl(&request)
            .await
            .unwrap_or_else(|error| panic!("{query}: {error}"));
        let funnel = crate::query_timing::current()
            .expect("request scope")
            .lock()
            .unwrap()
            .funnel
            .clone();
        let rows = answer["result"]["rows"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| panic!("{query}: no rows in {answer}"));
        Ok::<_, ()>((rows, funnel))
    })
    .await
    .unwrap()
}

fn sorted_uids(rows: &[Value]) -> Vec<String> {
    let mut uids = rows
        .iter()
        .map(|row| {
            row.get("metadata.uid")
                .or_else(|| row.pointer("/metadata/uid"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("row without metadata.uid: {row}"))
                .to_string()
        })
        .collect::<Vec<_>>();
    uids.sort();
    uids
}

fn sorted_rows(rows: &[Value]) -> Vec<String> {
    let mut rows = rows.iter().map(Value::to_string).collect::<Vec<_>>();
    rows.sort();
    rows
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn class_uid_pruning_over_a_clustered_hour_matches_the_unhinted_where_form() {
    // Pre-r13c cells clustered hour merges by (source, class) under this
    // layout; it is process-global, and native tests run one at a time.
    class_uid_pruning_over_a_clustered_hour("NANO_LAKE_COMPACTION_LAYOUT", "8192:67108864").await;
}

/// NAN-3437: the same reader contract over an hour clustered by the
/// independent switch (default row groups, one merge pass).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn class_uid_pruning_over_a_class_families_hour_matches_the_unhinted_where_form() {
    class_uid_pruning_over_a_clustered_hour(crate::part_ingest::merge::CLASS_FAMILIES_ENV, "1").await;
}

async fn class_uid_pruning_over_a_clustered_hour(env: &str, value: &str) {
    std::env::set_var(env, value);
    let root = tempfile::tempdir().unwrap();
    let hour = (Utc::now() - Duration::hours(8))
        .duration_trunc(Duration::hours(1))
        .unwrap();
    ingest_and_seal(root.path(), hour).await;
    let engine = engine(root.path()).await;

    let truth = (0..ROWS)
        .filter(|&i| class(i) == 4001 && port(i) == 445)
        .map(|i| format!("uid-{i:08}"))
        .collect::<Vec<_>>();
    assert!(!truth.is_empty());

    // Event rows: identical uids, and exactly the fixture truth.
    let (hinted, hinted_funnel) =
        run(&engine, "class_uid=4001 dst_endpoint.port=445", hour, true).await;
    // NAN-4159: the unhinted ground truth. A `where` on a computed eval
    // output carries no class hint, so nothing is pruned (NAN-4186 pushes
    // hints through a plain alias such as `eval c=class_uid`, so the alias
    // is computed: `class_uid+0`).
    let (plain, plain_funnel) = run(
        &engine,
        "dst_endpoint.port=445 | eval c=class_uid+0 | where c=4001",
        hour,
        true,
    )
    .await;
    // NAN-4155: `| where class_uid=N` pushes the class hint down.
    let (piped, piped_funnel) = run(
        &engine,
        "dst_endpoint.port=445 | where class_uid=4001",
        hour,
        true,
    )
    .await;
    assert_eq!(sorted_uids(&hinted), truth, "hinted rows equal truth");
    assert_eq!(sorted_uids(&plain), truth, "unhinted rows equal truth");
    assert_eq!(sorted_uids(&piped), truth, "where-form rows equal truth");
    assert!(
        hinted_funnel.source_family_pruned_files > 0,
        "the class hint pruned no file: is the hour part class-clustered? {hinted_funnel:?}"
    );
    assert_eq!(
        plain_funnel.source_family_pruned_files, 0,
        "the eval/where form carries no class hint"
    );
    // The funnel sums every selection of the walk, and the two forms walk
    // different chunk counts, so only "it prunes" is comparable.
    assert!(
        piped_funnel.source_family_pruned_files > 0,
        "the where form carries the class hint (NAN-4155): {piped_funnel:?}"
    );

    // The NAN-3188 aggregate shape.
    let (hinted, hinted_funnel) = run(&engine, "(class_uid=4001 activity_id=1) dst_endpoint.port=445 | stats count() as n by src_endpoint.hostname", hour, false).await;
    let (plain, _) = run(&engine, "dst_endpoint.port=445 | eval c=class_uid+0 | where c=4001 AND activity_id=1 | stats count() as n by src_endpoint.hostname", hour, false).await;
    assert!(!hinted.is_empty());
    assert_eq!(
        sorted_rows(&hinted),
        sorted_rows(&plain),
        "stats rows identical with and without pruning"
    );
    assert!(
        hinted_funnel.source_family_pruned_files > 0,
        "{hinted_funnel:?}"
    );
    let total = hinted
        .iter()
        .map(|row| {
            row["n"]
                .as_u64()
                .or_else(|| row["n"].as_str().and_then(|n| n.parse().ok()))
                .unwrap()
        })
        .sum::<u64>();
    assert_eq!(
        total,
        (0..ROWS)
            .filter(|&i| class(i) == 4001 && port(i) == 445 && i % 2 == 0)
            .count() as u64
    );
    eprintln!("nan3188 class prune ({env}={value}): hinted funnel {hinted_funnel:?}");
    std::env::remove_var(env);
}

/// NAN-4292: an event-id lookup over the class-families hour prunes files
/// by uid sidecar through the engine's positioned probe and still returns
/// exactly the one row, cold (layouts built) and warm (layouts cached).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn uid_lookup_prunes_files_by_sidecar_and_returns_the_row() {
    std::env::set_var(crate::part_ingest::merge::CLASS_FAMILIES_ENV, "1");
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    let root = tempfile::tempdir().unwrap();
    let hour = (Utc::now() - Duration::hours(8))
        .duration_trunc(Duration::hours(1))
        .unwrap();
    ingest_and_seal(root.path(), hour).await;
    let engine = engine(root.path()).await;
    for i in [0, 4_001, ROWS - 1] {
        let uid = format!("uid-{i:08}");
        for pass in ["cold", "warm"] {
            let (rows, funnel) = run(&engine, &format!("metadata.uid={uid}"), hour, true).await;
            assert_eq!(sorted_uids(&rows), vec![uid.clone()], "{uid} {pass}");
            assert!(funnel.uid_pruned_files > 0, "the uid sidecars pruned no file ({uid} {pass}): {funnel:?}");
        }
        let (rows, _) = run(&engine, &format!("metadata.uid={uid} | stats count() as n"), hour, false).await;
        let n = rows[0]["n"].as_u64().or_else(|| rows[0]["n"].as_str().and_then(|n| n.parse().ok()));
        assert_eq!(n, Some(1), "{uid}: {rows:?}");
    }
    // An absent id prunes every file and returns nothing.
    let (rows, funnel) = run(&engine, "metadata.uid=uid-absent", hour, true).await;
    assert!(rows.is_empty(), "{rows:?}");
    assert!(funnel.uid_pruned_files > 0, "{funnel:?}");
    std::env::remove_var("NANO_LAKE_UID_SIDECAR_WRITE");
    std::env::remove_var(crate::part_ingest::merge::CLASS_FAMILIES_ENV);
}
