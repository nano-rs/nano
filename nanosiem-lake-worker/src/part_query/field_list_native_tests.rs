// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3566, native: a low-volume log source must reach the search field
//! list. Many rows of source A and one row of source B are ingested and
//! sealed into one hour part (one source-family data file per source), then
//! read through the routes the field sidebar uses. The exact ones — the
//! per-field drill-in (`| stats count() by metadata.log_source`, also under
//! a `metadata.log_source=*` base) and the count rollup
//! (`/v1/aggregate/count`) — list both sources from the multi-file part. The
//! field-stats row sample (limit 1,000) need not, which is why search lists
//! low-cardinality fields from the exact routes.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::engine::field_list_native -- --ignored --nocapture --test-threads=1
//! ```

use crate::count_aggregate::CountAggregateRequest;
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
use std::collections::BTreeMap;
use std::sync::Arc;

const TENANT: &str = "6a2b8c4d-1e3f-4a5b-9c7d-2e4f6a8b0c13";
/// Source A's rows: more than the field-stats sample's 1,000-row bound, so
/// a newest-first sample alone could never be trusted to see source B.
const ROWS_A: usize = 1_500;
const SOURCE_A: &str = "audit";
const SOURCE_B: &str = "otlp_log";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(
        "lab-signer-nan3566",
        ed25519_dalek::SigningKey::from_bytes(&[66; 32]),
    )
    .unwrap()
}

fn event(i: usize, time: &str, source: &str) -> Value {
    let raw = format!("raw {source} event {i}");
    json!({
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201,
        "severity_id": 1, "time": time, "message": format!("{source} event {i}"),
        "raw_data_size": raw.len(), "raw_data": raw,
        "actor": {"user": {"name": format!("user{}", i % 7)}},
        "user": {"name": format!("user{}", i % 7), "uid": "S-1-5-21-1"},
        "src_endpoint": {"ip": format!("10.0.0.{}", i % 200), "hostname": format!("ws-{}.corp.local", i % 5)},
        "dst_endpoint": {"ip": "192.168.1.1", "port": 445},
        "status": "Success",
        "metadata": {"uid": format!("{source}-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
            "product": {"name": source, "vendor_name": "fixture"}},
    })
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

/// Source A spread over the hour; source B one row near its start, older
/// than the newest 1,000 rows (the reported shape: the rare event is not in
/// the field-stats sample).
fn bronze_batches(hour: DateTime<Utc>) -> Vec<Vec<Value>> {
    let at = |i: usize| (hour + Duration::milliseconds(i as i64 * 2_000)).to_rfc3339();
    let first = (0..ROWS_A / 2).map(|i| event(i, &at(i), SOURCE_A)).collect::<Vec<_>>();
    let rare = vec![event(0, &(hour + Duration::milliseconds(1_000)).to_rfc3339(), SOURCE_B)];
    let second = (ROWS_A / 2..ROWS_A).map(|i| event(i, &at(i), SOURCE_A)).collect::<Vec<_>>();
    vec![first, rare, second]
}

/// Ingest each bronze batch as its own source object, then advance the
/// clock until the sealed hour is a single hour part.
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
    for (n, batch) in bronze_batches(hour).into_iter().enumerate() {
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT)
            .expect("bronze admitted");
        let at = hour_ms + (n as i64 + 1) * 600_000;
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
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    let mut clock = hour_ms + 4 * 3_600_000;
    for _ in 0..600 {
        ingestor.tick(clock).await.expect("tick");
        clock += 1_000;
        let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
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
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3566-local";
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
        Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts"))),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap()
        .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29))
        .unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29))
        .unwrap();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
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

fn window(hour: DateTime<Utc>) -> (String, String) {
    ((hour - Duration::hours(1)).to_rfc3339(), (hour + Duration::hours(11)).to_rfc3339())
}

fn granted() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
    nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(TENANT.parse().unwrap(), Utc::now(), &[])
}

async fn rows(engine: &PartQueryEngine, query: &str, hour: DateTime<Utc>, limit: usize) -> Vec<Value> {
    let (start, end) = window(hour);
    let request = BroadNplRequest {
        request_id: "nan3566".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start,
        end,
        limit,
        offset: 0,
        table_view: false,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: Default::default(),
    };
    let answer = crate::query_timing::measure("nan3566", async {
        Ok::<_, ()>(crate::enrichment_read::scope(granted(), engine.broad_npl(&request)).await)
    })
    .await
    .unwrap()
    .unwrap_or_else(|error| panic!("{query}: {error}"));
    answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows in {answer}"))
}

fn log_source(row: &Value) -> Option<String> {
    row.get("metadata.log_source")
        .or_else(|| row.pointer("/metadata/log_source"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn count(value: &Value) -> u64 {
    value.as_u64().or_else(|| value.as_str().and_then(|value| value.parse().ok())).unwrap_or_else(|| panic!("count {value}"))
}

/// Value → count over `rows`, each row counted once (a row sample).
fn sampled_sources(rows: &[Value]) -> BTreeMap<String, u64> {
    let mut sources = BTreeMap::new();
    for row in rows {
        *sources.entry(log_source(row).unwrap_or_else(|| panic!("row without log_source: {row}"))).or_default() += 1;
    }
    sources
}

/// Value → count from grouped `stats count() as count by metadata.log_source` rows.
fn grouped_sources(rows: &[Value], alias: &str) -> BTreeMap<String, u64> {
    rows.iter()
        .map(|row| (log_source(row).or_else(|| row["value"].as_str().map(str::to_owned)).unwrap_or_else(|| panic!("group row {row}")), count(&row[alias])))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_one_row_source_in_a_multi_file_hour_part_reaches_every_field_list_route() {
    let root = tempfile::tempdir().unwrap();
    let hour = (Utc::now() - Duration::hours(8)).duration_trunc(Duration::hours(1)).unwrap();
    ingest_and_seal(root.path(), hour).await;

    // The fixture is the reported shape: one hour part, one data file per
    // source, the rare source in its own file.
    let parts = LocalObjectStore::new(root.path().join("parts")).unwrap();
    let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
    let part = live.parts().next().expect("one hour part").clone();
    let engine = engine(root.path()).await;
    let record = engine.fetcher().records(std::slice::from_ref(&part)).await.unwrap().remove(0);
    let files = record.files.data.iter().map(|file| (file.name.clone(), file.rows, file.log_sources.clone())).collect::<Vec<_>>();
    eprintln!("nan3566 hour part files: {files:?}");
    assert!(files.len() >= 2, "a multi-file hour part: {files:?}");
    assert!(
        files.iter().any(|(_, rows, sources)| *rows == 1 && sources.as_deref() == Some(&[SOURCE_B.to_string()][..])),
        "source B is a one-row file of its own: {files:?}"
    );
    let expected = BTreeMap::from([(SOURCE_A.to_string(), ROWS_A as u64), (SOURCE_B.to_string(), 1)]);

    // The main search finds the rare row.
    let direct = rows(&engine, &format!("metadata.log_source={SOURCE_B}"), hour, 100).await;
    assert_eq!(direct.len(), 1, "direct search: {direct:?}");

    // Per-field drill-in, as the search service sends it to the worker.
    for base in ["*", "metadata.log_source=*"] {
        let query = format!("{base} | stats count() as count by metadata.log_source | sort -count | head 100");
        let grouped = grouped_sources(&rows(&engine, &query, hour, 100).await, "count");
        assert_eq!(grouped, expected, "drill-in `{query}`");
    }

    // The exact count rollup the drill-in is served from.
    let (start, end) = window(hour);
    let request = CountAggregateRequest {
        request_id: "nan3566-count".into(),
        tenant_id: TENANT.into(),
        group_field: "metadata.log_source".into(),
        group_results: true,
        predicate: None,
        bucket_span_us: None,
        count_alias: "count".into(),
        start,
        end,
        source_filter: None,
        deny_source_types: Default::default(),
        max_groups: crate::count_aggregate::MAX_COUNT_GROUPS,
        group_by_source: false,
    };
    let counted = crate::query_timing::measure("nan3566-count", async {
        Ok::<_, ()>(crate::enrichment_read::scope(granted(), super::super::partials::count_aggregate(&engine, &request)).await)
    })
    .await
    .unwrap()
    .unwrap_or_else(|error| panic!("count aggregate: {error}"));
    let counted_rows = counted["result"]["rows"].as_array().cloned().unwrap_or_default();
    eprintln!("nan3566 count rows: {counted_rows:?}");
    assert_eq!(grouped_sources(&counted_rows, "count"), expected, "count rollup");

    // The field-stats row sample is any 1,000 matching rows (newest first
    // for full rows, unordered under a projection): whether it holds source
    // B is luck. The full-row sample here does not. This is why search lists
    // the low-cardinality fields from the exact routes above, not from it.
    let newest = sampled_sources(&rows(&engine, "*", hour, 1_000).await);
    assert_eq!(newest, BTreeMap::from([(SOURCE_A.to_string(), 1_000)]), "newest-rows sample");
    let projected = rows(&engine, "* | table metadata.log_source, class_uid, src_endpoint.ip", hour, 1_000).await;
    assert_eq!(projected.len(), 1_000, "projected sample is bounded");
    eprintln!("nan3566 projected sample: {:?}", sampled_sources(&projected));
}

/// NAN-3780: search plans `source_type IN (…) | stats count` as the
/// `metadata.log_source` count rollup with an `in` predicate (the lake
/// profile compiles `source_type` to that path). The rollup answer must equal
/// the raw scan of the caller's own text, for every subset of the sources,
/// including sources with no rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_source_type_in_list_count_from_the_rollup_matches_the_raw_scan() {
    let root = tempfile::tempdir().unwrap();
    let hour = (Utc::now() - Duration::hours(8)).duration_trunc(Duration::hours(1)).unwrap();
    ingest_and_seal(root.path(), hour).await;
    let engine = engine(root.path()).await;
    let (start, end) = window(hour);
    for (sources, expected) in [
        (vec![SOURCE_A, SOURCE_B, "windows_sysmon"], ROWS_A as u64 + 1),
        (vec![SOURCE_B], 1),
        (vec!["windows_sysmon", "apache_access"], 0),
    ] {
        let list = sources.join(", ");
        let raw = rows(&engine, &format!("source_type IN ({list}) | stats count() as count"), hour, 10).await;
        let raw = raw.first().map_or(0, |row| count(&row["count"]));
        assert_eq!(raw, expected, "raw scan of source_type IN ({list})");
        let request: CountAggregateRequest = serde_json::from_value(json!({
            "request_id": "nan3780-count",
            "tenant_id": TENANT,
            "group_field": "metadata.log_source",
            "group_results": false,
            "predicate": {"kind": "in", "values": sources},
            "count_alias": "count",
            "start": start,
            "end": end,
            "max_groups": 1,
        }))
        .unwrap();
        let counted = crate::query_timing::measure("nan3780-count", async {
            Ok::<_, ()>(crate::enrichment_read::scope(granted(), super::super::partials::count_aggregate(&engine, &request)).await)
        })
        .await
        .unwrap()
        .unwrap_or_else(|error| panic!("count aggregate ({list}): {error}"));
        let rolled = counted["result"]["rows"]
            .as_array()
            .and_then(|rows| rows.first())
            .map_or(0, |row| count(&row["count"]));
        assert_eq!(rolled, raw, "rollup vs raw for source_type IN ({list})");
    }
}
