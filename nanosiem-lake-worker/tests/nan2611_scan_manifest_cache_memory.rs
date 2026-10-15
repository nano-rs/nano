//! NAN-2611: the generation publisher's snapshot hydration must not keep
//! every parsed Iceberg manifest resident.
//!
//! iceberg 0.10.1 caches every manifest a scan parses in the table's
//! `ObjectCache`, whose 32 MiB capacity is weighed with `size_of_val` of the
//! `Manifest` struct: a shallow ~100-byte weight, so the "bound" admits every
//! manifest regardless of its entries and column statistics. A plan of a
//! table with ~1,500 manifests and wide OCSF column statistics held ~850 MiB
//! live on staging (manager RssAnon 188 -> 898 MiB during hydration, then
//! pinned by the allocator through the 40-minute build and the upload).
//!
//! This binary owns its global allocator, so the live-byte counter covers
//! exactly the scan below.
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
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed)
                + layout.size() as isize;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            let delta = new_size as isize - layout.size() as isize;
            let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

struct LocalObjects {
    root: std::path::PathBuf,
}

impl HttpFetch for LocalObjects {
    async fn fetch(
        &self,
        request: Request<Buffer>,
    ) -> opendal::Result<Response<HttpBody>> {
        let path = self.root.join(request.uri().path().trim_start_matches('/'));
        let bytes = match request.method().as_str() {
            "PUT" => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, request.body().to_bytes()).unwrap();
                Vec::new()
            }
            "GET" => std::fs::read(&path).map_err(|error| {
                opendal::Error::new(opendal::ErrorKind::NotFound, error.to_string())
            })?,
            method => panic!("unexpected fixture method {method}"),
        };
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

const COLUMNS: i32 = 120;
const MANIFESTS: usize = 240;

fn wide_schema() -> Schema {
    let mut fields = vec![Arc::new(NestedField::required(
        1,
        "time",
        Type::Primitive(PrimitiveType::Timestamptz),
    ))];
    for id in 2..=COLUMNS {
        fields.push(Arc::new(NestedField::optional(
            id,
            format!("column_{id}"),
            Type::Primitive(PrimitiveType::String),
        )));
    }
    Schema::builder().with_fields(fields).build().unwrap()
}

/// One data file with the per-column statistics a wide OCSF Parquet object
/// carries: counts plus lower/upper bounds for every column.
fn wide_data_file(index: usize) -> DataFile {
    let mut counts = HashMap::new();
    let mut lower = HashMap::new();
    let mut upper = HashMap::new();
    for id in 2..=COLUMNS {
        counts.insert(id, 1_000_u64);
        lower.insert(id, Datum::string(format!("{index:08}-lower-{id:04}-aaaaaaaaaaaaaaaa")));
        upper.insert(id, Datum::string(format!("{index:08}-upper-{id:04}-zzzzzzzzzzzzzzzz")));
    }
    DataFileBuilder::default()
        .content(DataContentType::Data)
        .file_path(format!("s3://bucket/warehouse/data/pack-{index}.parquet"))
        .file_format(DataFileFormat::Parquet)
        .partition(Struct::from_iter([Some(Literal::int(1))]))
        .record_count(1_000)
        .file_size_in_bytes(4 * 1024 * 1024)
        .partition_spec_id(0)
        .value_counts(counts.clone())
        .null_value_counts(counts)
        .lower_bounds(lower)
        .upper_bounds(upper)
        .build()
        .unwrap()
}

/// Plan every file of the current snapshot the way hydration does (streamed,
/// one task at a time) and report (peak during the plan, live bytes still
/// held once the plan is drained while the table is alive), both relative to
/// the live bytes before the plan.
async fn plan_heap(table: &iceberg::table::Table) -> (isize, isize, usize) {
    use futures::TryStreamExt;
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let mut tasks = table.scan().build().unwrap().plan_files().await.unwrap();
    let mut planned = 0;
    while let Some(task) = tasks.try_next().await.unwrap() {
        planned += 1;
        drop(task);
    }
    drop(tasks);
    // Let the scan's spawned manifest readers finish dropping their state.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    (
        PEAK.load(Ordering::SeqCst) - before,
        LIVE.load(Ordering::SeqCst) - before,
        planned,
    )
}

#[test]
fn hydration_scan_does_not_retain_parsed_manifests() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            iceberg_storage_opendal::install_http_client(HttpClient::with(LocalObjects {
                root: dir.path().into(),
            }))
            .unwrap();
            let catalog = MemoryCatalogBuilder::default()
                .with_storage_factory(Arc::new(OpenDalStorageFactory::S3 {
                    customized_credential_load: None,
                }))
                .load(
                    "nan2611",
                    HashMap::from([
                        (MEMORY_CATALOG_WAREHOUSE.into(), "s3://bucket/warehouse".into()),
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
                        .schema(wide_schema())
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
            // One fast-append commit per data file, as the tail compactor
            // registers packs: every commit adds one manifest.
            for index in 0..MANIFESTS {
                let tx = Transaction::new(&table);
                table = tx
                    .fast_append()
                    .with_check_duplicate(false)
                    .add_data_files([wide_data_file(index)])
                    .apply(tx)
                    .unwrap()
                    .commit(&catalog)
                    .await
                    .unwrap();
            }
            // A catalog-loaded table, exactly as hydration obtains it.
            let ident = table.identifier().clone();
            let loaded = catalog.load_table(&ident).await.unwrap();
            drop(table);

            let (cached_peak, cached_retained, cached_files) = plan_heap(&loaded).await;
            drop(loaded);
            // A second, independent load: its cache starts cold, so the plan
            // below parses every manifest again.
            let reloaded = catalog.load_table(&ident).await.unwrap();
            let scan_table =
                nanosiem_lake_worker::generation::uncached_scan_table(&reloaded).unwrap();
            drop(reloaded);
            let (uncached_peak, uncached_retained, uncached_files) = plan_heap(&scan_table).await;
            eprintln!(
                "NAN-2611 scan heap: manifests={MANIFESTS} columns={COLUMNS} \
                 cached_peak={cached_peak} cached_retained={cached_retained} \
                 uncached_peak={uncached_peak} uncached_retained={uncached_retained}"
            );
            assert_eq!(cached_files, MANIFESTS);
            assert_eq!(uncached_files, MANIFESTS);
            // The defect this guards: the default table keeps every parsed
            // manifest (tens of KiB each with wide statistics) resident.
            assert!(
                cached_retained > (MANIFESTS as isize) * 16 * 1024,
                "default table no longer retains manifests ({cached_retained} bytes); \
                 re-check whether uncached_scan_table is still needed"
            );
            // The hydration table retains nothing per manifest, and its plan
            // peak is a small fraction of the cached one.
            assert!(
                uncached_retained < 256 * 1024,
                "uncached scan retained {uncached_retained} bytes"
            );
            assert!(
                uncached_peak * 4 < cached_peak,
                "uncached plan peak {uncached_peak} is not bounded below cached {cached_peak}"
            );
        });
}
