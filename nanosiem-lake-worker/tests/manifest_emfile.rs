//! Exercise Iceberg's internal duplicate-check fan-out with real Avro manifests.
//! The local transport holds a real descriptor for each in-flight GET, making
//! EMFILE deterministic without relying on DNS speed or an external service.
use axum::http::{Request, Response};
use iceberg::io::*;
use iceberg::memory::{MEMORY_CATALOG_WAREHOUSE, MemoryCatalogBuilder};
use iceberg::spec::*;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation};
use iceberg_storage_opendal::OpenDalStorageFactory;
use opendal::{
    Buffer,
    raw::{HttpBody, HttpClient, HttpFetch},
};
use std::{
    collections::HashMap,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Counts {
    retry_once: AtomicBool,
    slow: AtomicBool,
    active: AtomicUsize,
    peak: AtomicUsize,
    emfile: AtomicUsize,
}
struct LocalObjects {
    root: std::path::PathBuf,
    counts: Arc<Counts>,
}
impl HttpFetch for LocalObjects {
    async fn fetch(&self, request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let path = self.root.join(request.uri().path().trim_start_matches('/'));
        if request.method() == "GET" && self.counts.retry_once.swap(false, Ordering::SeqCst) {
            return Ok(Response::builder()
                .status(503)
                .header("content-length", 0)
                .body(HttpBody::new(futures::stream::empty(), Some(0)))
                .unwrap());
        }
        let mut bytes = Vec::new();
        let result = match request.method().as_str() {
            "PUT" => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, request.body().to_bytes())
            }
            "GET" => match std::fs::File::open(&path) {
                Ok(mut file) => {
                    let active = self.counts.active.fetch_add(1, Ordering::SeqCst) + 1;
                    self.counts.peak.fetch_max(active, Ordering::SeqCst);
                    if self.counts.slow.load(Ordering::SeqCst)
                        && path.extension().is_some_and(|x| x == "avro")
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    let result = file.read_to_end(&mut bytes).map(|_| ());
                    self.counts.active.fetch_sub(1, Ordering::SeqCst);
                    result
                }
                Err(error) => Err(error),
            },
            method => panic!("unexpected fixture method {method}"),
        };
        if let Err(error) = result {
            if error.raw_os_error() == Some(libc::EMFILE) {
                self.counts.emfile.fetch_add(1, Ordering::SeqCst);
            }
            return Err(
                opendal::Error::new(opendal::ErrorKind::Unexpected, error.to_string())
                    .set_source(error),
            );
        }
        let len = bytes.len();
        Ok(Response::builder()
            .status(200)
            .header("content-length", len)
            .header("etag", "\"fixture\"")
            .body(HttpBody::new(
                futures::stream::iter([Ok(Buffer::from(bytes))]),
                Some(len as u64),
            ))
            .unwrap())
    }
}

#[test]
fn compaction_with_600_manifests_under_soft_256() {
    const CHILD: &str = "NAN2498_MANIFEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compaction_with_600_manifests_under_soft_256",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("DEPLOYMENT_MODE")
            .env("NANO_LAKE_MANIFEST_FETCH_CONCURRENCY", "64")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let expected_limit: usize = std::env::var("NANO_LAKE_MANIFEST_FETCH_CONCURRENCY")
                .unwrap()
                .parse()
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let counts = Arc::new(Counts::default());
            iceberg_storage_opendal::install_http_client(HttpClient::with(LocalObjects {
                root: dir.path().into(),
                counts: counts.clone(),
            }))
            .unwrap();
            let catalog = MemoryCatalogBuilder::default()
                .with_storage_factory(Arc::new(OpenDalStorageFactory::S3 {
                    customized_credential_load: None,
                }))
                .load(
                    "emfile",
                    HashMap::from([
                        (
                            MEMORY_CATALOG_WAREHOUSE.into(),
                            "s3://bucket/warehouse".into(),
                        ),
                        (S3_ENDPOINT.into(), "http://fixture.invalid".into()),
                        (S3_ACCESS_KEY_ID.into(), "fixture".into()),
                        (S3_SECRET_ACCESS_KEY.into(), "fixture".into()),
                        (S3_REGION.into(), "us-east-1".into()),
                        (S3_PATH_STYLE_ACCESS.into(), "true".into()),
                    ]),
                )
                .await
                .unwrap();
            let ns = NamespaceIdent::new("nano".into());
            catalog.create_namespace(&ns, HashMap::new()).await.unwrap();
            let mut table = catalog
                .create_table(
                    &ns,
                    TableCreation::builder()
                        .name("events".into())
                        .schema(
                            Schema::builder()
                                .with_fields([Arc::new(NestedField::required(
                                    1,
                                    "time",
                                    Type::Primitive(PrimitiveType::Timestamptz),
                                ))])
                                .build()
                                .unwrap(),
                        )
                        .partition_spec(
                            UnboundPartitionSpec::builder()
                                .with_spec_id(0)
                                .add_partition_fields([UnboundPartitionField::builder()
                                    .source_id(1)
                                    .field_id(1000)
                                    .name("event_hour".into())
                                    .transform(Transform::Hour)
                                    .build()])
                                .unwrap()
                                .build(),
                        )
                        .build(),
                )
                .await
                .unwrap();
            let data_file = |index| {
                DataFileBuilder::default()
                    .content(DataContentType::Data)
                    .file_path(format!("s3://bucket/warehouse/data/pack-{index}.parquet"))
                    .file_format(DataFileFormat::Parquet)
                    .partition(Struct::from_iter([Some(Literal::int(1))]))
                    .record_count(1)
                    .file_size_in_bytes(100)
                    .partition_spec_id(0)
                    .build()
                    .unwrap()
            };
            for index in 0..600 {
                let tx = Transaction::new(&table);
                table = tx
                    .fast_append()
                    .with_check_duplicate(false)
                    .add_data_files([data_file(index)])
                    .apply(tx)
                    .unwrap()
                    .commit(&catalog)
                    .await
                    .unwrap();
            }
            let list = table
                .manifest_list_reader(table.metadata().current_snapshot().unwrap())
                .load()
                .await
                .unwrap();
            assert_eq!(list.entries().len(), 600);
            let mut limits = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
                0
            );
            limits.rlim_cur = 256;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
            counts.peak.store(0, Ordering::SeqCst);
            counts.slow.store(true, Ordering::SeqCst);
            // Execute the actual compactor registration path, including its
            // default duplicate check and snapshot publication fences.
            let observation = iceberg_storage_opendal::manifest_fetch::Observation::start();
            use nanosiem_lake_worker::iceberg::{
                TailIdentityProfile, register_compacted_staged_file_for,
            };
            use sha2::{Digest, Sha256};
            let pack_id = "b".repeat(64);
            let object_sha = "c".repeat(64);
            let file_path = format!(
                "{}/data/tail/tenant_sha256={}/hour=1/pack-{pack_id}-{object_sha}.parquet",
                table.metadata().location(),
                hex::encode(Sha256::digest(b"tenant-a"))
            );
            let result = register_compacted_staged_file_for(
                &catalog,
                table.identifier(),
                TailIdentityProfile::Ocsf,
                "tenant-a",
                &pack_id,
                &object_sha,
                &file_path,
                1,
                100,
                1,
            )
            .await;
            assert!(
                result.is_ok(),
                "compaction commit failed: {result:?}; EMFILE={}",
                counts.emfile.load(Ordering::SeqCst)
            );
            assert_eq!(counts.emfile.load(Ordering::SeqCst), 0);
            assert!(
                counts.peak.load(Ordering::SeqCst) <= expected_limit,
                "peak={}",
                counts.peak.load(Ordering::SeqCst)
            );
            let metrics = observation.snapshot();
            assert!(metrics.manifests_fetched >= 601, "{metrics:?}");
            assert_eq!(metrics.retries, 0);
            assert!(
                metrics.max_concurrent > 1 && metrics.max_concurrent <= expected_limit,
                "{metrics:?}"
            );
            eprintln!(
                "600 manifests, soft=256, transport peak={}, EMFILE=0, committed; {metrics:?}",
                counts.peak.load(Ordering::SeqCst)
            );
            drop(observation);

            // Scan planning uses the same transport admission as transaction
            // validation. Query/generation scan readers must not bypass the gate.
            use futures::TryStreamExt;
            assert_eq!(result.unwrap().status, "compacted");
            let table = catalog.load_table(table.identifier()).await.unwrap();
            let scan = iceberg_storage_opendal::manifest_fetch::Observation::start();
            let mut tasks = table.scan().build().unwrap().plan_files().await.unwrap();
            let mut files = 0;
            while tasks.try_next().await.unwrap().is_some() {
                files += 1;
            }
            assert_eq!(files, 601);
            assert_eq!(counts.emfile.load(Ordering::SeqCst), 0);
            assert!(scan.snapshot().max_concurrent <= expected_limit);
            eprintln!("scan planned {files} files; {:?}", scan.snapshot());
            drop(scan);

            // Exercise the real OpenDAL RetryLayer and count its retry, while
            // keeping admission through the failed attempt and subsequent read.
            let retry = iceberg_storage_opendal::manifest_fetch::Observation::start();
            counts.retry_once.store(true, Ordering::SeqCst);
            let list_path = table.metadata().current_snapshot().unwrap().manifest_list();
            assert!(
                !table
                    .file_io()
                    .new_input(list_path)
                    .unwrap()
                    .read()
                    .await
                    .unwrap()
                    .is_empty()
            );
            let metrics = retry.snapshot();
            assert_eq!(metrics.manifests_fetched, 1);
            assert_eq!(metrics.retries, 1);
            assert_eq!(metrics.max_concurrent, 1);
            eprintln!("injected HTTP 503 recovered; {metrics:?}");
        });
}

#[test]
fn configured_manifest_limit_is_enforced() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "compaction_with_600_manifests_under_soft_256",
            "--nocapture",
        ])
        .env("NAN2498_MANIFEST_CHILD", "1")
        .env_remove("DEPLOYMENT_MODE")
        .env("NANO_LAKE_MANIFEST_FETCH_CONCURRENCY", "8")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
}
