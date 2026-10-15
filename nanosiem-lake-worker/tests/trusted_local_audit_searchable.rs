// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed the actual Vector fixture's Parquet into production ingest and native
//! query. Run open-lean-audit-vector.py with NANO_AUDIT_TEST_BRONZE_OUTPUT first.
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::{
    enrichment::BronzeIngestEnricher,
    executor::{ExecutorMode, NativeExecutor},
    native::NativeChdb,
    part_ingest::{
        ingest::{seed_schema, IngestConfig, Ingestor},
        SourceNotice, SpoolQueue,
    },
    part_query::{
        engine::{BroadNplRequest, EngineSettings, PartQueryEngine},
        fetch::{parts_key_prefix, PartFetcher, StoreObjectSource},
        log_view::PartLogView,
    },
    parts::{
        part_log::{LocalObjectStore, ObjectStore},
        provenance::LocalPartSigner,
    },
    reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires disposable Vector fixture output and verified native chDB/compiler"]
async fn vector_audit_bronze_is_searchable_and_delivery_replay_is_deduplicated() {
    let bronze = PathBuf::from(std::env::var("NANO_LOCAL_AUDIT_BRONZE_DIR").unwrap());
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(bronze.join("manifest.json")).unwrap()).unwrap();
    let tenant = manifest["tenant"].as_str().unwrap();
    Uuid::parse_str(tenant).unwrap();
    let events = manifest["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    let now_ms = events[0]["time"].as_i64().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let sources = LocalObjectStore::new(dir.path().join("sources")).unwrap();
    let parts = Arc::new(LocalObjectStore::new(dir.path().join("parts")).unwrap());
    let signer =
        LocalPartSigner::new("open-audit-fixture", SigningKey::from_bytes(&[7; 32])).unwrap();
    let queue = SpoolQueue::new(dir.path().join("spool"), tenant).unwrap();
    let mut keys = Vec::new();
    let mut fixture_files = Vec::new();
    for file in std::fs::read_dir(&bronze).unwrap() {
        let file = file.unwrap().path();
        if file
            .extension()
            .is_some_and(|extension| extension == "parquet")
        {
            fixture_files.push(file.clone());
            let key = format!("bronze/{}", file.file_name().unwrap().to_str().unwrap());
            sources
                .put(&key, &std::fs::read(file).unwrap())
                .await
                .unwrap();
            keys.push(key);
        }
    }
    assert!(
        !keys.is_empty(),
        "fixture must contain actual Vector Parquet"
    );
    let admission = nanosiem_lake_worker::bronze::admit_bronze_files(&fixture_files, tenant)
        .expect("actual Vector Parquet must pass production bronze admission");
    assert_eq!(admission.batch.len(), 3);
    let mut config = IngestConfig::new(tenant, dir.path().join("ingest"));
    config.prevalence_enabled = false;
    config.flush_interval_override_ms = Some(1);
    let mut ingest = Ingestor::open(
        config,
        parts.as_ref(),
        &sources,
        &queue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now_ms,
    )
    .await
    .unwrap();
    // Lost delivery acknowledgement republishes the same uid in new bronze
    // objects. A different notice version exercises the durable ingest ledger.
    for version in ["first", "retry"] {
        for key in &keys {
            queue
                .deliver(&SourceNotice {
                    tenant_id: tenant.into(),
                    key: key.clone(),
                    version: version.into(),
                    bytes: 0,
                    sha256: None,
                    edge_sha256: None,
                    notified_at_ms: now_ms,
                })
                .unwrap();
        }
        let report = ingest.tick(now_ms + 1000).await.unwrap();
        assert_eq!(report.admitted_rows, 3, "{version}: {report:?}");
        assert_eq!(report.duplicates, if version == "retry" { 3 } else { 0 });
        ingest.flush_now(now_ms + 1000).await.unwrap();
    }
    drop(ingest);
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    // Native executor retains thread-local state until process exit.
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(
        runtime,
        1,
        "open-audit-proof",
        ExecutorMode::ReadOnly,
    )
    .unwrap();
    let store: Arc<dyn ObjectStore> = parts;
    let view = PartLogView::open(store.as_ref(), tenant, signer.trusted())
        .await
        .unwrap();
    let bucket = "open-audit-fixture";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: dir.path().join("query-cache"),
            max_bytes: 128 << 20,
            query_max_bytes: 128 << 20,
            fetch_concurrency: 2,
            fetch_deadline: Duration::from_secs(30),
        },
        tenant,
        bucket,
        &parts_key_prefix(tenant).unwrap(),
        Arc::new(StoreObjectSource::local(
            bucket,
            store.clone(),
            dir.path().join("parts"),
        )),
    )
    .unwrap();
    let fetcher = PartFetcher::new(tenant, bucket, store.clone(), signer.trusted(), cache).unwrap();
    let engine = PartQueryEngine::new(
        EngineSettings {
            tenant_id: tenant.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
            max_query_bytes: 128 << 20,
            max_memory_bytes: 1 << 30,
            max_execution_seconds: 30,
            threads: 1,
        },
        store,
        view,
        fetcher,
        executor,
    )
    .unwrap();
    let at = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap();
    let request = |query: String| BroadNplRequest {
        request_id: Uuid::new_v4().to_string(),
        tenant_id: tenant.into(),
        dataset: "logs".into(),
        query,
        start: (at - chrono::Duration::hours(1)).to_rfc3339(),
        end: (at + chrono::Duration::hours(1)).to_rfc3339(),
        limit: 50,
        offset: 0,
        table_view: false,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: BTreeMap::new(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: BTreeSet::new(),
    };
    let count = engine
        .broad_npl(&request("metadata.log_source=audit".into()))
        .await
        .unwrap();
    assert_eq!(
        count["result"]["result_rows"], 3,
        "retry must not duplicate searchable rows"
    );
    for event in events {
        let query = format!(
            "metadata.log_source=audit class_uid={} metadata.uid=\"{}\"",
            event["class_uid"],
            event["metadata"]["uid"].as_str().unwrap()
        );
        let result = engine.broad_npl(&request(query)).await.unwrap();
        assert_eq!(
            result["result"]["result_rows"], 1,
            "every class retains its original audit identity"
        );
    }
}
