// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3003: lean `ingest[T]` admits the nano platform stamps the
//! collector-v2 and zero platform bases write on every lake row
//! (`metadata.nano_parser_bundle_sha256`, `metadata.nano_credential_id`).
//!
//! The rows under `tests/fixtures/nan3003/` are the REAL output of each base's
//! `ocsf_lake_storage_prepare` VRL run in the pinned cell Vector image
//! (`regenerate.sh`). Before the fix the strict OCSF 1.9 check in bronze
//! normalize refused every v2/zero-v2 row as `attribute_unknown`.
//!
//! The native query test (ignored by default) needs NANO_CHDB_LIBRARY_PATH,
//! NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER.

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::bronze::admit_bronze_files;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, TenantKeySet};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const BUNDLE: &str = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
const CREDENTIAL: &str = "0b7f7a5e-3c1d-4f7e-9a2b-1c2d3e4f5a6b";
/// Every platform base shape: v1, zero, collector-v2, zero + collector-v2
/// (pinned and unpinned cell).
const BASES: &[&str] = &[
    "v1-base",
    "zero-base",
    "collector-v2-base",
    "zero-collector-v2-base",
    "zero-collector-v2-base-unpinned",
];

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-test-0001", SigningKey::from_bytes(&[11; 32])).unwrap()
}

fn trusted() -> TenantKeySet {
    signer().trusted()
}

/// The base's sink-stage rows, with a per-base uid (the fixtures share
/// `nan3003-a`/`-b`) and a recent event time.
fn base_rows(base: &str, time: &str) -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/nan3003/{base}.jsonl"));
    std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut row: Value = serde_json::from_str(line).unwrap();
            let uid = format!("{base}/{}", row["metadata"]["uid"].as_str().unwrap());
            row["metadata"]["uid"] = json!(uid);
            row["time"] = json!(time);
            row
        })
        .collect()
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut encoded = Vec::new();
    for event in events {
        serde_json::to_writer(&mut encoded, event).unwrap();
        encoded.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(encoded.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(encoded)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap())
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// Malformed stamps: each must be refused, never stored or silently dropped.
fn malformed() -> Vec<(&'static str, Value)> {
    vec![
        ("uppercase-sha", json!({"nano_parser_bundle_sha256": BUNDLE.to_ascii_uppercase()})),
        ("short-sha", json!({"nano_parser_bundle_sha256": &BUNDLE[..63]})),
        ("non-hex-sha", json!({"nano_parser_bundle_sha256": format!("{}g", &BUNDLE[..63])})),
        ("numeric-sha", json!({"nano_parser_bundle_sha256": 7})),
        ("uppercase-credential", json!({"nano_credential_id": CREDENTIAL.to_ascii_uppercase()})),
        ("braced-credential", json!({"nano_credential_id": format!("{{{CREDENTIAL}}}")})),
        // A sibling that is NOT a known platform stamp stays refused.
        ("unknown-sibling", json!({"nano_parser_bundle_forged": BUNDLE})),
    ]
}

fn malformed_row(name: &str, metadata: &Value, time: &str) -> Value {
    let mut row = base_rows("zero-collector-v2-base", time).remove(1);
    row["metadata"]["uid"] = json!(format!("malformed/{name}"));
    let stamped = row["metadata"].as_object_mut().unwrap();
    stamped.remove("nano_parser_bundle_sha256");
    for (key, value) in metadata.as_object().unwrap() {
        stamped.insert(key.clone(), value.clone());
    }
    row
}

#[test]
fn every_platform_base_row_is_admitted_with_its_stamps() {
    let directory = tempfile::tempdir().unwrap();
    for base in BASES {
        let path = directory.path().join(format!("{base}.parquet"));
        write_bronze(&path, &base_rows(base, "2026-09-28T12:00:00Z"));
        let admitted = admit_bronze_files(&[path], TENANT)
            .unwrap_or_else(|error| panic!("{base}: lean admission refused a base row: {error:#}"));
        let rows = admitted.batch.rows();
        assert_eq!(rows.len(), 2, "{base}");
        for row in rows {
            let metadata = &row.ocsf_event["metadata"];
            let expected_bundle = (*base == "zero-collector-v2-base").then_some(BUNDLE);
            assert_eq!(metadata["nano_parser_bundle_sha256"].as_str(), expected_bundle, "{base}: {metadata}");
            if base.contains("collector-v2") && row.event_uid.ends_with("nan3003-a") {
                assert_eq!(metadata["nano_credential_id"], CREDENTIAL, "{base}");
            } else {
                assert!(metadata.get("nano_credential_id").is_none(), "{base}: {metadata}");
            }
        }
    }
}

#[test]
fn malformed_platform_stamps_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    for (name, metadata) in malformed() {
        let path = directory.path().join(format!("{name}.parquet"));
        write_bronze(&path, &[malformed_row(name, &metadata, "2026-09-28T12:00:00Z")]);
        let error = admit_bronze_files(&[path], TENANT).expect_err(name);
        let text = format!("{error:#}");
        let field = metadata.as_object().unwrap().keys().next().unwrap().clone();
        assert!(text.contains(&format!("metadata.{field}")), "{name}: {text}");
    }
}

/// Drive every base fixture plus every malformed row through `ingest[T]` into
/// signed parts under `root/parts`, asserting admission and the read schema.
async fn ingest_all(root: &Path, now: chrono::DateTime<chrono::Utc>) {
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let time = (now - chrono::Duration::seconds(30)).to_rfc3339();

    let mut keys = Vec::new();
    for base in BASES {
        let key = format!("bronze/{base}.parquet");
        write_bronze(&sources_dir.join(&key), &base_rows(base, &time));
        keys.push(key);
    }
    let bad = malformed();
    for (name, metadata) in &bad {
        let key = format!("bronze/malformed-{name}.parquet");
        write_bronze(&sources_dir.join(&key), &[malformed_row(name, metadata, &time)]);
        keys.push(key);
    }

    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
    for key in &keys {
        spool.deliver(&SourceNotice {
            tenant_id: TENANT.into(), key: key.clone(), version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: now_ms,
        }).unwrap();
    }
    let report = ingestor.tick(now_ms + 1_000).await.unwrap();
    ingestor.flush_now(now_ms + 5_000).await.unwrap();
    assert_eq!(report.admitted_rows, 2 * BASES.len() as u64, "every base row is admitted");
    assert_eq!(ingestor.health().rows_rejected_total, bad.len() as u64, "every malformed stamp is refused");
    assert!(spool.pending(1).await.unwrap().is_empty(), "every notice is settled");

    // The tenant read schema carries the stamps as queryable string leaves.
    let schema = ingestor.schema().clone();
    let arrow_schema::DataType::Struct(metadata) = schema.field_with_name("metadata").unwrap().data_type().clone() else {
        panic!("metadata is a struct");
    };
    for field in ["nano_parser_bundle_sha256", "nano_credential_id"] {
        let leaf = metadata.iter().find(|leaf| leaf.name() == field).unwrap_or_else(|| panic!("{field} in schema"));
        assert_eq!(leaf.data_type(), &arrow_schema::DataType::Utf8, "{field}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ingest_writes_platform_stamps_into_signed_parts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    ingest_all(root, chrono::Utc::now()).await;
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();

    // Read the signed parts back from the object store.
    let live = load_log(&parts, TENANT).await.unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut stored = BTreeMap::new();
    for part in live.parts() {
        let part_keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let bytes = parts.get(&part_keys.data(index)).await.unwrap().unwrap();
            let path = scratch.path().join(format!("{}-{index}.parquet", part.part_id));
            std::fs::write(&path, bytes).unwrap();
            let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap().build().unwrap();
            for batch in reader {
                let mut encoded = Vec::new();
                let mut writer = LineDelimitedWriter::new(&mut encoded);
                writer.write(&batch.unwrap()).unwrap();
                writer.finish().unwrap();
                for line in String::from_utf8(encoded).unwrap().lines() {
                    let row: Value = serde_json::from_str(line).unwrap();
                    let metadata = &row["metadata"];
                    stored.insert(
                        metadata["uid"].as_str().unwrap().to_string(),
                        (
                            metadata.get("nano_parser_bundle_sha256").and_then(Value::as_str).map(str::to_string),
                            metadata.get("nano_credential_id").and_then(Value::as_str).map(str::to_string),
                        ),
                    );
                }
            }
        }
    }
    assert_eq!(stored.len(), 2 * BASES.len(), "{stored:#?}");
    for (uid, (bundle, credential)) in &stored {
        let base = uid.split('/').next().unwrap();
        let expected_bundle = (base == "zero-collector-v2-base").then(|| BUNDLE.to_string());
        let expected_credential = (base.contains("collector-v2") && uid.ends_with("nan3003-a")).then(|| CREDENTIAL.to_string());
        assert_eq!(bundle, &expected_bundle, "{uid}");
        assert_eq!(credential, &expected_credential, "{uid}");
    }
    assert!(!stored.keys().any(|uid| uid.starts_with("malformed/")), "no malformed row is stored");
}

/// The stamps are queryable by name through the native part query engine
/// (`query[T]`): filter and group by the parser bundle and the credential.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn platform_stamps_are_queryable_natively() {
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::collections::BTreeSet;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let now = chrono::Utc::now();
    ingest_all(root, now).await;

    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted()).await.unwrap();
    let bucket = "nan3003-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: root.join("query-cache"), max_bytes: 256 << 20, query_max_bytes: 256 << 20,
        fetch_concurrency: 2, fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted(), cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan3003-native", ExecutorMode::ReadOnly).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 256 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 60, threads: 1,
    }, store, view, fetcher, executor).unwrap();
    let start = (now - chrono::Duration::minutes(10)).to_rfc3339();
    let end = (now + chrono::Duration::minutes(10)).to_rfc3339();
    let run = |query: String| {
        let request = BroadNplRequest {
            request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
            dataset: "logs".into(), query, start: start.clone(), end: end.clone(),
            limit: 10, offset: 0, table_view: false, use_cache: false,
            cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
            clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
        };
        let engine = &engine;
        async move { engine.broad_npl(&request).await.unwrap_or_else(|error| panic!("{}: {error:#}", request.query)) }
    };
    let count = |value: &Value| value["result"]["rows"][0]["count"].as_u64();
    assert_eq!(count(&run("* | stats count".into()).await), Some(2 * BASES.len() as u64));
    let by_bundle = run(format!("metadata.nano_parser_bundle_sha256=\"{BUNDLE}\" | stats count")).await;
    assert_eq!(count(&by_bundle), Some(2), "{by_bundle}");
    let by_credential = run(format!("metadata.nano_credential_id=\"{CREDENTIAL}\" | stats count")).await;
    // collector-v2-base, zero-collector-v2-base and its unpinned twin each
    // attribute their first row.
    assert_eq!(count(&by_credential), Some(3), "{by_credential}");
    let grouped = run("* | stats count by metadata.nano_parser_bundle_sha256".into()).await;
    eprintln!("grouped: {grouped}");
}
