// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reproducible cold-reader fixture. No databases or tenant credentials.
use super::*;
use crate::part_query::fetch::*;
use crate::parts::part_log::{LocalObjectStore, ObjectStore, PartRef};
use crate::parts::provenance::tests::{sample_record, signer, TENANT};
use crate::parts::provenance::{FileDigest, PartSigner, SignedProvenance};
use crate::parts::sha256_hex;
use crate::reader_object_cache::ReaderObjectCacheSettings;
use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use parquet::arrow::ArrowWriter;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Mythos-shaped cold production reader benchmark; downloads public chDB if no library supplied"]
async fn mythos_cold_reader() {
    benchmark_layout(40_000, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "8K row-group comparison on the production reader"]
async fn mythos_eight_k_layout() {
    benchmark_layout(8_192, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "NAN-4829 billable HTTP request accounting through production R2ReaderObjectSource"]
async fn mythos_r2_requests() {
    benchmark_layout(40_000, true).await;
}

/// Loopback S3 transport: the actual production reader issues its HTTP ranges.
/// Provenance still uses LocalObjectStore (one remote GET per cold part in the
/// cost model); counts here deliberately exclude that separate metadata path.
struct WireStore {
    source: Arc<dyn crate::reader_object_cache::ReaderObjectSource>,
    requests: Arc<std::sync::Mutex<Vec<(String, String, u64)>>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for WireStore {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl WireStore {
    async fn open(root: std::path::PathBuf) -> Self {
        use axum::{
            body::Body,
            extract::{Path, State},
            http::{HeaderMap, Method, Response},
            routing::get,
            Router,
        };
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        type Requests = Arc<std::sync::Mutex<Vec<(String, String, u64)>>>;
        async fn read(
            State((root, requests)): State<(std::path::PathBuf, Requests)>,
            Path(key): Path<String>,
            method: Method,
            headers: HeaderMap,
        ) -> Response<Body> {
            let mut file = tokio::fs::File::open(root.join(key.strip_prefix("bucket/").unwrap()))
                .await
                .unwrap();
            let bytes = file.metadata().await.unwrap().len();
            let range = headers
                .get("range")
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("bytes=")
                .unwrap();
            let (start, end) = range.split_once('-').unwrap();
            let start: u64 = start.parse().unwrap();
            let end = end.parse::<u64>().unwrap() + 1;
            assert!(start < end && end <= bytes);
            requests
                .lock()
                .unwrap()
                .push((method.to_string(), key, end - start));
            file.seek(std::io::SeekFrom::Start(start)).await.unwrap();
            let mut body = vec![0; (end - start) as usize];
            file.read_exact(&mut body).await.unwrap();
            Response::builder()
                .status(206)
                .header(
                    "content-range",
                    format!("bytes {start}-{}/{bytes}", end - 1),
                )
                .header("content-length", body.len())
                .body(Body::from(body))
                .unwrap()
        }
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*key}", get(read))
            .with_state((root, requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let service = opendal::services::S3::default()
            .bucket("bucket")
            .region("auto")
            .endpoint(&format!("http://{addr}"))
            .access_key_id("fixture")
            .secret_access_key("fixture");
        let operator = opendal::Operator::new(service)
            .unwrap()
            .layer(crate::r2_ops::layer())
            .finish();
        Self {
            source: Arc::new(crate::reader_object_cache::R2ReaderObjectSource::new(
                operator, "bucket",
            )),
            requests,
            server,
        }
    }
    fn snapshot(&self) -> (usize, usize, usize, u64) {
        let requests = self.requests.lock().unwrap();
        assert!(
            requests.iter().all(|(method, _, _)| method == "GET"),
            "bounded ranges must not HEAD"
        );
        let manifests = requests
            .iter()
            .filter(|(_, key, _)| key.ends_with(".json"))
            .count();
        (
            requests.len(),
            manifests,
            requests.len() - manifests,
            requests.iter().map(|(_, _, bytes)| bytes).sum(),
        )
    }
}

async fn benchmark_layout(group_rows: usize, use_wire: bool) {
    let root = tempfile::tempdir().unwrap();
    let library = match std::env::var("NANO_CHDB_LIBRARY_PATH") {
        Ok(path) => std::path::PathBuf::from(path),
        Err(_) => {
            let archive = root.path().join("chdb.tar.gz");
            assert!(std::process::Command::new("curl").args(["-fsSL", "--retry", "3", "https://github.com/chdb-io/chdb-core/releases/download/v26.7.0/linux-x86_64-libchdb.tar.gz", "-o"]).arg(&archive).status().unwrap().success());
            assert_eq!(
                sha256_hex(&std::fs::read(&archive).unwrap()),
                "4ba2b740f2b107be53157d8226cae1edb25b498d69511cdb3c340db3c95c2905"
            );
            assert!(std::process::Command::new("tar")
                .arg("-xzf")
                .arg(archive)
                .arg("-C")
                .arg(root.path())
                .arg("libchdb.so")
                .status()
                .unwrap()
                .success());
            root.path().join("libchdb.so")
        }
    };
    let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256")
        .unwrap_or_else(|_| sha256_hex(&std::fs::read(&library).unwrap()));
    let runtime = crate::native::NativeChdb::load_verified(library, &digest).unwrap();
    std::mem::forget(runtime.clone());
    let executor = crate::executor::NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts",
        crate::executor::ExecutorMode::ReadOnly,
        Some(1 << 30),
    )
    .unwrap();
    let source_root = root.path().join("source");
    let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
    let signer = signer(7);
    let metadata_fields = Fields::from(vec![
        Field::new("uid", DataType::Utf8, false),
        Field::new("log_source", DataType::Utf8, false),
    ]);
    let schema = Arc::new(Schema::new(vec![
        Field::new(
            "time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("metadata", DataType::Struct(metadata_fields.clone()), false),
        Field::new("host", DataType::Utf8, false),
        Field::new("process", DataType::Utf8, false),
        Field::new("raw_data", DataType::Utf8, false),
    ]));
    let mut wanted = Vec::new();
    let (mut parquet_bytes, mut footer_bytes, mut manifest_bytes) = (0_u64, 0_u64, 0_u64);
    let fixture_started = std::time::Instant::now();
    for file in 0..28 {
        let mut record = sample_record();
        record.part_id = crate::parts::format::PartId::parse(&format!(
            "{}-9f86d081884c7d65",
            1790330400123_u64 + file
        ))
        .unwrap();
        let path = root.path().join("fixture.parquet");
        let props = crate::parts::format::ParquetSettings {
            zstd_level: 3,
            row_group_rows: group_rows,
            max_file_bytes: 256 << 20,
        }
        .writer_properties(
            80_000,
            &record.part_id,
            record.level,
            TENANT,
            &record.schema_fingerprint,
        )
        .unwrap();
        let mut writer = ArrowWriter::try_new(
            std::fs::File::create(&path).unwrap(),
            schema.clone(),
            Some(props),
        )
        .unwrap();
        for group in 0..2 {
            let base = file as usize * 80_000 + group * 40_000;
            let rows = base..base + 40_000;
            let raw = rows.clone().map(|i| {
                let mut s = format!("event={i} ");
                let mut seed = i as u64 + 1;
                for _ in 0..24 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    s.push_str(&format!(
                        "Image=svchost.exe User=CORP\\svc session={seed:016x} "
                    ));
                }
                s
            });
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(
                        TimestampMicrosecondArray::from_iter_values(
                            rows.clone().map(|i| 1_790_330_400_000_000 + i as i64),
                        )
                        .with_timezone("UTC"),
                    ) as ArrayRef,
                    Arc::new(StructArray::new(
                        metadata_fields.clone(),
                        vec![
                            Arc::new(StringArray::from_iter_values(
                                rows.clone().map(|i| format!("uid-{i:08}")),
                            )),
                            Arc::new(StringArray::from_iter_values(
                                rows.clone().map(|_| "sysmon"),
                            )),
                        ],
                        None,
                    )),
                    Arc::new(StringArray::from_iter_values(
                        rows.clone().map(|i| format!("host-{:04}", i % 1000)),
                    )),
                    Arc::new(StringArray::from_iter_values(rows.map(|i| {
                        if i == 7 || i == 1_120_007 {
                            "rare.exe"
                        } else {
                            "svchost.exe"
                        }
                    }))),
                    Arc::new(StringArray::from_iter_values(raw)),
                ],
            )
            .unwrap();
            writer.write(&batch).unwrap();
        }
        writer.close().unwrap();
        let body = std::fs::read(&path).unwrap();
        let ranges = crate::parts::parquet_ranges::build(&path).unwrap();
        record.rows = 80_000;
        record.min_time_us = 1_790_330_400_000_000 + file as i64 * 80_000;
        record.max_time_us = record.min_time_us + 79_999;
        record.hours[0].min_time_us = record.min_time_us;
        record.files.data[0].min_time_us = record.min_time_us;
        record.hours[0].rows = record.rows;
        record.hours[0].max_time_us = record.max_time_us;
        record.dedup.rows_in = record.rows;
        record.files.data[0].rows = record.rows;
        record.files.data[0].max_time_us = record.max_time_us;
        record.files.data[0].row_groups = 80_000_usize.div_ceil(group_rows) as u32;
        record.files.data[0].bytes = body.len() as u64;
        record.files.data[0].sha256 = sha256_hex(&body);
        record.files.data[0].class_id = Some(if file % 2 == 0 { 1007 } else { 4001 });
        record.files.data[0].log_sources = Some(vec!["sysmon".into()]);
        let keys = crate::parts::format::PartKeys::new(
            TENANT,
            record.level,
            record.event_hour,
            &record.part_id,
        )
        .unwrap();
        store
            .put(&keys.file("data-00000.parquet"), &body)
            .await
            .unwrap();
        let manifest = serde_json::to_vec(&ranges).unwrap();
        parquet_bytes += body.len() as u64;
        footer_bytes += ranges.last().unwrap().bytes;
        manifest_bytes += manifest.len() as u64;
        store
            .put(&keys.file("ranges-00000.json"), &manifest)
            .await
            .unwrap();
        record.files.data[0].parquet_ranges = Some(FileDigest {
            name: "ranges-00000.json".into(),
            bytes: manifest.len() as u64,
            sha256: sha256_hex(&manifest),
        });
        let signature = signer
            .sign(TENANT, std::slice::from_ref(&record))
            .await
            .unwrap()
            .remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted())
            .unwrap()
            .to_bytes()
            .unwrap();
        store.put(&keys.provenance(), &signed).await.unwrap();
        wanted.push((
            PartRef::from_record(&record, &sha256_hex(&signed), true),
            PartFile::Data(0),
        ));
    }
    let wire = if use_wire {
        Some(WireStore::open(source_root.clone()).await)
    } else {
        None
    };
    println!(
        "NAN4829 fixture group_rows={group_rows} files=28 groups={} rows=2240000 hosts=1000 parquet_bytes={parquet_bytes} footer_bytes={footer_bytes} manifest_bytes={manifest_bytes} build_s={:.3}",
        28 * 80_000_usize.div_ceil(group_rows),
        fixture_started.elapsed().as_secs_f64()
    );
    for (label, predicate, files, expected) in [
        ("H1", "metadata.uid = 'uid-00000007'", 1, 1),
        ("H8", "process = 'rare.exe'", 28, 2),
        (
            "H10",
            "metadata.uid IN ('uid-00000007','uid-01120007')",
            28,
            2,
        ),
        ("host", "host = 'host-0007'", 28, 2240),
        ("scan", "1", 28, 2_240_000),
    ] {
        let cache = crate::reader_object_cache::ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: root.path().join(format!("cache-{label}")),
                max_bytes: 8 << 30,
                query_max_bytes: 8 << 30,
                fetch_concurrency: 4,
                fetch_deadline: std::time::Duration::from_secs(120),
            },
            TENANT,
            "bucket",
            &parts_key_prefix(TENANT).unwrap(),
            wire.as_ref()
                .map(|wire| wire.source.clone())
                .unwrap_or_else(|| {
                    Arc::new(StoreObjectSource::local(
                        "bucket",
                        store.clone(),
                        source_root.clone(),
                    ))
                }),
        )
        .unwrap();
        let fetcher =
            PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap();
        let wire_before = wire.as_ref().map(WireStore::snapshot);
        let started = std::time::Instant::now();
        let local = fetcher.ensure_files(&wanted[..files]).await.unwrap();
        let fetch_ms = started.elapsed().as_secs_f64() * 1000.;
        let mut paths = local
            .files
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let source = crate::planner::local_path_spec(&mut paths).unwrap();
        let sql = format!("SELECT count() AS n, sum(length(raw_data)) AS payload FROM file({{source:String}}, Parquet) WHERE {predicate} SETTINGS max_threads=2, input_format_parquet_filter_push_down=1");
        let output = executor
            .execute(crate::planner::NativeQueryPlan {
                query_sha256: "0".repeat(64),
                sql,
                params: vec![("source".into(), source)],
                budget: crate::planner::QueryBudget {
                    candidate_objects: files,
                    estimated_scan_bytes: 0,
                    max_query_bytes: 8 << 30,
                },
                native_event_rows: false,
                temporary_aliases: Default::default(),
                schema_defaults: Vec::new(),
                reader: Default::default(),
            })
            .await
            .unwrap();
        let wall_ms = started.elapsed().as_secs_f64() * 1000.;
        let answer: serde_json::Value = serde_json::from_slice(&output.data).unwrap();
        assert_eq!(
            answer["n"]
                .as_u64()
                .or_else(|| answer["n"].as_str().and_then(|s| s.parse().ok()))
                .unwrap(),
            expected
        );
        let stats = fetcher.cache().stats();
        println!("NAN4829 baseline hunt={label} wall_ms={wall_ms:.3} fetch_ms={fetch_ms:.3} exec_ms={:.3} fetched_bytes={} GETs={} decoded_bytes={} rows_read={}", wall_ms-fetch_ms, stats.fetched_bytes, stats.misses + files as u64, output.storage_bytes_read, output.storage_rows_read);
        if let (Some(wire), Some(before)) = (&wire, wire_before) {
            let after = wire.snapshot();
            println!(
                "NAN4829 wire baseline hunt={label} data_GETs={} provenance_GETs={files} bytes={}",
                after.0 - before.0,
                after.3 - before.3
            );
        }
        if label != "scan" {
            table_hunt(
                root.path(),
                store.clone(),
                &source_root,
                &wanted[..files],
                &executor,
                &schema,
                label,
                predicate,
                expected as usize,
                wire.as_ref(),
            )
            .await;
        }
    }
}

async fn table_hunt(
    root: &std::path::Path,
    store: Arc<LocalObjectStore>,
    source_root: &std::path::Path,
    wanted: &[(PartRef, PartFile)],
    executor: &crate::executor::NativeExecutor,
    schema: &Arc<Schema>,
    label: &str,
    predicate: &str,
    expected: usize,
    wire: Option<&WireStore>,
) {
    let start = chrono::DateTime::from_timestamp_micros(1_790_330_400_000_000).unwrap();
    let compiled = crate::planner::CompiledQuery {
        schema_version: 1, profile: "ocsf".into(), dataset: "logs".into(), source_placeholder: "__nano_lake_source__".into(),
        query_sha256: "0".repeat(64), start: start.to_rfc3339(), end: (start + chrono::Duration::hours(1)).to_rfc3339(), limit: 5000,
        table_view: true, newest_first_event_rows: true, stats_page: false,
        candidate_hints: vec![crate::planner::CandidateHint::SourceFamily { value: "sysmon".into() }],
        required_columns: ["host", "process", "raw_data", "metadata.uid", "time"].map(|name| crate::planner::RequiredColumn { name: name.into(), field_type: if name == "time" { "timestamp" } else { "string" }.into() }).into(),
        projected_scan_columns: vec![if label == "host" { "host" } else if label == "H8" { "process" } else { "metadata.uid" }.into(), "time".into()],
        sql: format!("SELECT host, process, raw_data, \"metadata.uid\", time FROM __nano_lake_source__ WHERE {} ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 5000 SETTINGS max_threads=2, max_execution_time=120", predicate.replace("metadata.uid", "\"metadata.uid\"")),
    };
    let two = crate::part_query::two_pass::plan(&compiled).expect("production two-pass plan");
    let field_types = crate::generation::schema_leaf_types(schema);
    let mut oracle = None;
    for mode in ["whole", "late"] {
        let signer = signer(7);
        let cache = crate::reader_object_cache::ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: root.join(format!("table-{label}-{mode}")),
                max_bytes: 8 << 30,
                query_max_bytes: 8 << 30,
                fetch_concurrency: 4,
                fetch_deadline: std::time::Duration::from_secs(120),
            },
            TENANT,
            "bucket",
            &parts_key_prefix(TENANT).unwrap(),
            wire.map(|wire| wire.source.clone()).unwrap_or_else(|| {
                Arc::new(StoreObjectSource::local(
                    "bucket",
                    store.clone(),
                    source_root.to_path_buf(),
                ))
            }),
        )
        .unwrap();
        let fetcher =
            PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap();
        let view = crate::part_query::log_view::PartLogView::open(
            store.as_ref(),
            TENANT,
            signer.trusted(),
        )
        .await
        .unwrap();
        let engine = PartQueryEngine::new(
            EngineSettings {
                tenant_id: TENANT.into(),
                bucket: "bucket".into(),
                compiler: "/bin/false".into(),
                max_query_bytes: 64 << 30,
                max_memory_bytes: 1 << 30,
                max_execution_seconds: 120,
                threads: 2,
            },
            store.clone(),
            view,
            fetcher,
            executor.clone(),
        )
        .unwrap();
        let scope = if mode == "late" {
            crate::part_query::range_fetch::scope_for(&compiled, &field_types)
        } else {
            None
        };
        if mode == "late" {
            assert!(scope.as_ref().unwrap().late_materialization());
        }
        let wire_before = wire.map(WireStore::snapshot);
        let started = std::time::Instant::now();
        let local = match &scope {
            Some(scope) => engine
                .fetcher
                .ensure_ranged(wanted, scope, false)
                .await
                .unwrap(),
            None => engine.fetcher.ensure_files(wanted).await.unwrap(),
        };
        let mut objects = Vec::new();
        let mut cache_objects = BTreeMap::new();
        let mut paths = Vec::new();
        for file in &local.files {
            let part = wanted
                .iter()
                .find(|(part, _)| part.part_id == file.part_id)
                .unwrap()
                .0
                .clone();
            let record = local.records.get(&part.part_id).unwrap();
            let key = engine.fetcher.file_uri(&part, record, file.file).unwrap();
            objects.push(crate::planner::ManifestObject {
                event_object_key: key.clone(),
                event_object_version: file.sha256.clone(),
                event_object_bytes: file.bytes,
                rows: record.rows,
                available_paths: field_types.keys().cloned().collect::<Vec<_>>().into(),
                field_types: field_types.clone(),
                column_compressed_bytes: Default::default(),
            });
            cache_objects.insert(
                key,
                crate::planner::SnapshotCacheObject {
                    version_id: file.sha256.clone(),
                    bytes: file.bytes,
                    path: file.path.clone(),
                },
            );
            paths.push(file.path.to_string_lossy().into_owned());
        }
        let mut tenant = engine.limits_tenant();
        tenant.snapshot_cache = Some(crate::planner::SnapshotCache {
            source_spec: crate::planner::local_path_spec(&mut paths).unwrap(),
            bytes: local.files.iter().map(|f| f.bytes).sum(),
            objects: cache_objects,
            read_schema: Some(crate::iceberg::clickhouse_read_schema(schema).unwrap()),
            bootstrap: false,
        });
        let selection = Selection {
            parts: wanted.iter().map(|(p, _)| p.clone()).collect(),
            manifest: crate::planner::SourceManifest::from_objects(TENANT, objects),
            tenant,
            candidates: None,
            field_types: field_types.clone(),
            evidence: Default::default(),
            object_times: Default::default(),
            _leases: vec![local],
        };
        let wire_narrow = wire.map(WireStore::snapshot);
        let run = crate::part_query::range_fetch::with_scope(
            scope.clone(),
            engine.run_two_pass(&selection, &two, None, None),
        )
        .await
        .unwrap()
        .expect("production two-pass execution");
        let wall_ms = started.elapsed().as_secs_f64() * 1000.;
        assert_eq!(run.rows.len(), expected);
        if let Some(oracle) = &oracle {
            assert_eq!(&run.rows, oracle, "{label} row-for-row payload equality");
        } else {
            oracle = Some(run.rows.clone());
        }
        let stats = engine.fetcher.cache().stats();
        println!("NAN4829 table mode={mode} hunt={label} wall_ms={wall_ms:.3} fetch_ms={:.3} exec_ms={:.3} fetched_bytes={} GETs={} decoded_bytes={} rows_read={} materialize_ms={:.3}", stats.fetch_ns as f64/1e6, run.engine_seconds*1000., stats.fetched_bytes, stats.misses + wanted.len() as u64, run.storage_bytes, run.storage_rows, run.materialize_seconds*1000.);
        if let (Some(wire), Some(before), Some(narrow)) = (wire, wire_before, wire_narrow) {
            let after = wire.snapshot();
            println!("NAN4829 wire mode={mode} hunt={label} narrow_GETs={} manifest_GETs={} predicate_and_footer_GETs={} payload_GETs={} total_cache_GETs={} provenance_GETs={} bytes={}", narrow.0-before.0, narrow.1-before.1, narrow.2-before.2, after.0-narrow.0, after.0-before.0, wanted.len(), after.3-before.3);
            if mode == "late" {
                let warm = futures::future::try_join_all((0..16).map(|_| async {
                    let local = engine
                        .fetcher
                        .ensure_ranged(wanted, scope.as_ref().unwrap(), false)
                        .await
                        .unwrap();
                    drop(local);
                    crate::part_query::range_fetch::with_scope(
                        scope.clone(),
                        engine.run_two_pass(&selection, &two, None, None),
                    )
                    .await
                }))
                .await
                .unwrap();
                for run_warm in warm {
                    assert_eq!(run_warm.unwrap().rows, run.rows);
                }
                assert_eq!(
                    wire.snapshot(),
                    after,
                    "16 warm agents must issue zero HTTP requests"
                );
                println!("NAN4829 wire warm hunt={label} agents=16 GETs=0 rows_equal=true");
            }
        }
        if mode == "late" && label == "H1" {
            // Model a reader much smaller than the writer, through the same
            // materializer and native payload planner used in production.
            let original_path = selection
                .tenant
                .snapshot_cache
                .as_ref()
                .unwrap()
                .objects
                .values()
                .next()
                .unwrap()
                .path
                .to_string_lossy()
                .into_owned();
            let ids = [crate::part_query::two_pass::RowId {
                path: original_path,
                row: 7,
            }];
            let roots = field_types
                .keys()
                .filter_map(|path| path.split('.').next())
                .map(str::to_string)
                .collect();
            let scope = crate::part_query::range_fetch::derive_scope(&two.payload, &roots).unwrap();
            let payload = engine
                .fetcher
                .materialize_payload(&selection, &ids, &scope, 64 << 10, 2)
                .await
                .unwrap();
            assert_eq!(
                payload.ids[0].row, 7,
                "oversized dictionaries retain native row offsets"
            );
            let mut plan =
                PartQueryEngine::plan_fenced(&payload.selection, &two.payload, None, None).unwrap();
            plan.params.push((
                crate::part_query::two_pass::ROW_IDS_PARAM.into(),
                crate::part_query::two_pass::ids_param(&payload.ids),
            ));
            let output = engine.run(plan).await.unwrap();
            let rows = decode_rows(&output.data).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["metadata.uid"], "uid-00000007");
        }
    }
}
