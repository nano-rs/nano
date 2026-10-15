// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3153: entity-pivot counts answered from the parts' count rollups are
//! identical to the compiled scan of the same nPL (and its `| where` form).
//!
//! Rows from three sources are ingested through `ingest[T]` into several
//! signed parts (the newest one is the freshest data: there is no separate
//! un-rolled tail, every part carries its rollup partial). Every shape the
//! search service routes to the rollups on a lean cell is compared, group for
//! group, with `broad_npl` over windows that are bucket-aligned, ragged at
//! both edges, inside one 5-minute bucket (no rollup bucket at all) and open
//! up to "now" over the newest part:
//! - `host=<dotless> | stats count by metadata.log_source` (`host_eq`: the
//!   name and its FQDNs, never `ws-10…`/`ws-1x`) and its FQDN form;
//! - `host=<dotless> | timechart span=10m count`;
//! - `source=S | stats count by src_endpoint.ip` (grouped by value);
//! - `user=U | stats count`;
//! - `A=v OR B=v | stats count by metadata.log_source` over two rollup
//!   fields, reassembled exactly as the search service does: per source
//!   `|A|+|B|` where one side is empty, a narrowed raw scan where both match
//!   (rows matching both fields in one row are counted once).
//!
//! Run: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER,
//! `cargo test -p nanosiem-lake-worker --test lean_rollup_routing_native -- --ignored --nocapture`

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::count_aggregate::CountAggregateRequest;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::part_query::partials;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, TenantKeySet};
use nanosiem_lake_worker::planner::{CountPredicate, CountPredicateKind};
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const TENANT: &str = "0a8f1d3c-7b2e-4f6a-9c1d-5e4b3a2f1e53";
const ROWS: usize = 4_500;
const STEP_MS: i64 = 600;
const PARTS: usize = 3;
const SOURCES: [&str; 3] = ["windows_sysmon", "conduit_proxy", "aws_cloudtrail"];
const IP: &str = "10.1.3.147";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-test-3153", SigningKey::from_bytes(&[31; 32])).unwrap()
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

/// Row `i`: hosts that do and do not match the dotless `ws-1` expansion,
/// users on two fields that co-occur only in windows_sysmon, and an IP that
/// is the source in proxy rows, the destination in sysmon rows, and both on
/// some proxy rows.
fn row(i: usize, time: &str) -> Value {
    let source = SOURCES[i % 3];
    let mut row = json!({
        "activity_id": 1, "class_uid": 3002, "class_name": "Authentication", "category_uid": 3,
        "severity": "Informational", "severity_id": 1, "time": time,
        "raw_data": format!("event {i}"),
        "raw_data_size": format!("event {i}").len(),
        "activity_name": "Logon", "category_name": "Identity & Access Management", "type_uid": 300201,
        "status": "Success", "status_id": 1,
        "metadata": {"uid": format!("uid-{i:06}"), "version": "1.9.0", "profiles": ["host"], "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": "Lab", "vendor_name": "Nano"}},
        "src_endpoint": {"ip": if i % 6 == 1 { IP.to_string() } else { format!("10.0.{}.{}", i % 7, i % 250) }},
        "dst_endpoint": {"ip": if i % 9 == 0 || i % 18 == 1 { IP.to_string() } else { format!("192.0.2.{}", i % 200) }},
    });
    let host = match i % 7 {
        0 => Some("ws-1"),
        1 => Some("ws-1.corp.local"),
        2 => Some("WS-1.Corp.Local"),
        3 => Some("ws-10.corp.local"),
        4 => Some("ws-1x"),
        5 => None,
        _ => Some("other.corp.local"),
    };
    if let Some(host) = host {
        row["device"] = json!({"hostname": host, "type_id": 2});
    }
    // Authentication requires `user`; svc_db is never a proxy user.
    let user = match (source, i % 5) {
        ("conduit_proxy", _) => "web",
        (_, 0) => "svc_db",
        (_, 1) => "SVC_DB",
        (_, 2) => "alice",
        _ => "svc_dbx",
    };
    row["user"] = json!({"name": user});
    if source != "aws_cloudtrail" {
        match i % 4 {
            0 => row["actor"] = json!({"user": {"name": "svc_db"}}),
            1 => row["actor"] = json!({"user": {"name": "bob"}}),
            _ => {}
        }
    }
    row
}

fn notice(key: &str, at_ms: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: at_ms,
    }
}

async fn engine_over(root: &Path, rows: &[Value], now: chrono::DateTime<chrono::Utc>) -> PartQueryEngine {
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
    for (index, chunk) in rows.chunks(rows.len().div_ceil(PARTS)).enumerate() {
        let key = format!("bronze/{index:04}.parquet");
        write_bronze(&sources_dir.join(&key), chunk);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).unwrap();
        let at = now_ms + index as i64 * 11_000;
        spool.deliver(&notice(&key, at)).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    let live = load_log(&parts, TENANT).await.unwrap();
    assert!(live.parts().count() >= 2, "several signed parts were published");
    drop(ingestor);

    let trusted: TenantKeySet = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "rollup-routing-local";
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
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "rollup-routing", ExecutorMode::ReadOnly).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 256 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 60, threads: 1,
    }, store, view, fetcher, executor).unwrap()
}

fn npl(query: &str, start: &str, end: &str) -> BroadNplRequest {
    BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: start.into(), end: end.into(),
        limit: 100_000, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    }
}

struct Count<'a> {
    field: &'a str,
    group_results: bool,
    group_by_source: bool,
    predicate: Option<(CountPredicateKind, &'a str)>,
    span_us: Option<i64>,
    source_filter: Option<&'a str>,
}

async fn rollup(engine: &PartQueryEngine, count: &Count<'_>, start: &str, end: &str) -> Value {
    let request = CountAggregateRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        tenant_id: TENANT.into(),
        group_field: count.field.into(),
        group_results: count.group_results,
        predicate: count.predicate.map(|(kind, value)| CountPredicate { kind, values: vec![value.into()] }),
        bucket_span_us: count.span_us,
        count_alias: "count".into(),
        start: start.into(),
        end: end.into(),
        source_filter: count.source_filter.map(Into::into),
        deny_source_types: BTreeSet::new(),
        max_groups: 100_000,
        group_by_source: count.group_by_source,
    };
    partials::count_aggregate(engine, &request).await.unwrap_or_else(|error| panic!("count_aggregate: {error}"))
}

/// `group key (all non-count columns) → count`, zero counts dropped (a
/// compiled timechart fills empty buckets; the count route does not).
fn groups(rows: &Value) -> BTreeMap<String, u64> {
    rows.as_array()
        .unwrap_or_else(|| panic!("rows: {rows}"))
        .iter()
        .filter_map(|row| {
            let object = row.as_object().unwrap();
            let count = object["count"].as_u64().or_else(|| object["count"].as_str().and_then(|v| v.parse().ok())).unwrap();
            let key = object
                .iter()
                .filter(|(name, _)| name.as_str() != "count")
                .map(|(name, value)| {
                    let name = if matches!(name.as_str(), "_time" | "time" | "time_bucket" | "timestamp") { "time" } else { name.as_str() };
                    let value = value.as_str().map(|v| v.replace('T', " ").trim_end_matches('Z').to_string())
                        .map(|v| v.split('.').next().unwrap().to_string())
                        .map_or_else(|| value.to_string(), |v| v);
                    format!("{name}={value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            (count > 0).then_some((key, count))
        })
        .collect()
}

/// `metadata.log_source → count` of source-grouped rows.
fn by_source(rows: &Value) -> BTreeMap<Option<String>, u64> {
    rows.as_array().unwrap().iter().map(|row| {
        (row["metadata.log_source"].as_str().map(str::to_string), row["count"].as_u64().unwrap())
    }).collect()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn rollup_routed_entity_counts_equal_the_compiled_scan() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let now = chrono::Utc::now();
    // 37 s past a 5-minute boundary, 45 minutes of rows ending ~2 min ago.
    let base_secs = (now.timestamp() / 300 - 10) * 300 + 37;
    let base = chrono::DateTime::from_timestamp(base_secs, 0).unwrap();
    let rows = (0..ROWS)
        .map(|i| row(i, &(base + chrono::Duration::milliseconds(i as i64 * STEP_MS)).to_rfc3339()))
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_over(dir.path(), &rows, now).await;
    let at = |seconds: f64| {
        (base + chrono::Duration::milliseconds((seconds * 1_000.0) as i64)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    };
    let aligned = |minutes: i64| {
        chrono::DateTime::from_timestamp(base_secs - 37 + minutes * 60, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let windows = [
        // Whole rollup buckets only (plus the 1 µs inclusive end edge).
        (aligned(5), aligned(35)),
        // Ragged at both ends.
        (at(100.0), at(2_000.5)),
        // Inside one bucket: no rollup bucket, all raw edge.
        (at(400.0), at(500.0)),
        // Everything up to "now", across the newest part.
        (at(-60.0), now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        // Before the data to a ragged end inside the newest part.
        (aligned(-10), at(2_600.3)),
    ];
    let mut compared = 0;
    for (start, end) in &windows {
        // (count-route request, compiled nPL, optional `| where` form)
        let shapes: Vec<(Count, String, Option<String>)> = vec![
            (
                Count { field: "device.hostname", group_results: false, group_by_source: true,
                        predicate: Some((CountPredicateKind::HostEq, "ws-1")), span_us: None, source_filter: None },
                r#"device.hostname="ws-1" | stats count by metadata.log_source"#.into(),
                None,
            ),
            (
                Count { field: "device.hostname", group_results: false, group_by_source: true,
                        predicate: Some((CountPredicateKind::Eq, "WS-1.corp.local")), span_us: None, source_filter: None },
                r#"device.hostname="WS-1.corp.local" | stats count by metadata.log_source"#.into(),
                Some(r#"* | where lower(device.hostname)="ws-1.corp.local" | stats count by metadata.log_source"#.into()),
            ),
            (
                Count { field: "device.hostname", group_results: false, group_by_source: false,
                        predicate: Some((CountPredicateKind::HostEq, "ws-1")), span_us: Some(600_000_000), source_filter: None },
                r#"device.hostname="ws-1" | timechart span=10m count"#.into(),
                None,
            ),
            (
                Count { field: "src_endpoint.ip", group_results: true, group_by_source: false,
                        predicate: None, span_us: None, source_filter: Some("conduit_proxy") },
                "metadata.log_source=conduit_proxy | stats count by src_endpoint.ip".into(),
                Some(r#"* | where metadata.log_source="conduit_proxy" | stats count by src_endpoint.ip"#.into()),
            ),
            (
                Count { field: "user.name", group_results: false, group_by_source: false,
                        predicate: Some((CountPredicateKind::Eq, "svc_db")), span_us: None, source_filter: None },
                r#"user.name="svc_db" | stats count"#.into(),
                Some(r#"* | where lower(user.name)="svc_db" | stats count"#.into()),
            ),
            (
                Count { field: "src_endpoint.ip", group_results: false, group_by_source: true,
                        predicate: Some((CountPredicateKind::Eq, IP)), span_us: None, source_filter: None },
                format!(r#"src_endpoint.ip="{IP}" | stats count by metadata.log_source"#),
                Some(format!(r#"* | where src_endpoint.ip="{IP}" | stats count by metadata.log_source"#)),
            ),
        ];
        for (count, query, where_query) in shapes {
            let routed = rollup(&engine, &count, start, end).await;
            let compiled = engine.broad_npl(&npl(&query, start, end)).await.unwrap_or_else(|e| panic!("{query}: {e:#}"));
            let (routed_groups, compiled_groups) = (groups(&routed["result"]["rows"]), groups(&compiled["result"]["rows"]));
            assert_eq!(routed_groups, compiled_groups, "{query} over [{start}, {end}]\nrouted {}\ncompiled {}", routed["result"]["rows"], compiled["result"]["rows"]);
            assert!(!compiled_groups.is_empty() || start.ends_with("00:00Z"), "{query} over [{start}, {end}] matched nothing");
            if let Some(where_query) = where_query {
                let scanned = engine.broad_npl(&npl(&where_query, start, end)).await.unwrap_or_else(|e| panic!("{where_query}: {e:#}"));
                assert_eq!(routed_groups, groups(&scanned["result"]["rows"]), "{where_query} over [{start}, {end}]");
            }
            compared += 1;
        }
        // Independent oracle: the dotless expansion is exactly the name and
        // its FQDNs (never `ws-10.corp.local` or `ws-1x`), counted in Rust.
        let fqdn_only = rollup(&engine, &Count { field: "device.hostname", group_results: false, group_by_source: false,
            predicate: Some((CountPredicateKind::HostEq, "ws-1")), span_us: None, source_filter: None }, start, end).await;
        let (from, to) = (
            chrono::DateTime::parse_from_rfc3339(start).unwrap().timestamp_millis(),
            chrono::DateTime::parse_from_rfc3339(end).unwrap().timestamp_millis(),
        );
        let expected = (0..ROWS)
            .filter(|i| matches!(i % 7, 0..=2))
            .filter(|i| (from..=to).contains(&(base.timestamp_millis() + *i as i64 * STEP_MS)))
            .count() as u64;
        assert_eq!(fqdn_only["result"]["rows"], json!([{"count": expected}]), "host_eq over [{start}, {end}]");

        // Two-field unions, reassembled exactly as the search service does.
        for (left, right, value) in [("user.name", "actor.user.name", "svc_db"), ("src_endpoint.ip", "dst_endpoint.ip", IP)] {
            let query = format!(r#"{left}="{value}" OR {right}="{value}""#);
            let side = |field: &'static str| Count { field, group_results: false, group_by_source: true,
                predicate: Some((CountPredicateKind::Eq, value)), span_us: None, source_filter: None };
            let (left_counts, right_counts) = (
                by_source(&rollup(&engine, &side(left), start, end).await["result"]["rows"]),
                by_source(&rollup(&engine, &side(right), start, end).await["result"]["rows"]),
            );
            let mut union = BTreeMap::new();
            let mut overlap = Vec::new();
            for source in left_counts.keys().chain(right_counts.keys()).collect::<BTreeSet<_>>() {
                let (l, r) = (left_counts.get(source).copied().unwrap_or(0), right_counts.get(source).copied().unwrap_or(0));
                if l > 0 && r > 0 {
                    overlap.push(source.clone().expect("a fixture source"));
                } else if l + r > 0 {
                    union.insert(source.clone(), l + r);
                }
            }
            if !overlap.is_empty() {
                let narrowed = format!(
                    "({query}) metadata.log_source IN ({}) | stats count by metadata.log_source",
                    overlap.iter().map(|source| format!("\"{source}\"")).collect::<Vec<_>>().join(", ")
                );
                let scanned = engine.broad_npl(&npl(&narrowed, start, end)).await.unwrap_or_else(|e| panic!("{narrowed}: {e:#}"));
                for (source, count) in by_source(&scanned["result"]["rows"]) {
                    if source.as_ref().is_some_and(|source| overlap.contains(source)) {
                        union.insert(source, count);
                    }
                }
            }
            let compiled = engine.broad_npl(&npl(&format!("{query} | stats count by metadata.log_source"), start, end)).await.unwrap();
            assert_eq!(union, by_source(&compiled["result"]["rows"]), "{query} over [{start}, {end}] (overlap {overlap:?})");
            // Same-row matches really occur in the fixture, so the naive sum
            // would be wrong for the overlapping source.
            let naive: u64 = left_counts.values().chain(right_counts.values()).sum();
            let exact: u64 = union.values().sum();
            eprintln!("{query} [{start}, {end}]: overlap {overlap:?}, exact {exact}, naive {naive}");
            compared += 1;
        }
    }
    eprintln!("{compared} rollup-routed shapes matched the compiled scan");
}
