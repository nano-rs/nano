// SPDX-License-Identifier: AGPL-3.0-or-later

//! Run with the isolated MinIO/REST fixture in fixtures/lean-iceberg-export.
//! No production endpoints are accepted and remote error bodies are not printed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use anyhow::Result;
use arrow_array::{Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema as ArrowSchema};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use futures::TryStreamExt;
use iceberg::io::FileIO;
use iceberg::spec::{
    DataContentType, DataFile, DataFileBuilder, DataFileFormat, NestedField, PrimitiveType, Schema,
    Struct, Type,
};
use iceberg::table::Table;
use iceberg::{Catalog, TableCreation};
use nanosiem_lake_worker::iceberg::CatalogConfig;
use nanosiem_lake_worker::part_ingest::export::{
    ExportFile, ExportHour, ExportManifest, IcebergCommitter,
};
use nanosiem_lake_worker::part_ingest::iceberg_export::{
    schema::{SchemaContract, FROZEN},
    ExportTable, ExportTarget, RestIcebergCommitter,
};
use nanosiem_lake_worker::parts::format::PARTS_ROOT;
use nanosiem_lake_worker::rest_commit::RestTableCommitClient;
use parquet::arrow::ArrowWriter;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const HOUR: &str = "0000000000001-aaaaaaaaaaaaaaaa";
const DAY: &str = "0000000000002-bbbbbbbbbbbbbbbb";
const EVOLVED: &str = "0000000000004-dddddddddddddddd";
const ERASED: &str = "0000000000003-cccccccccccccccc";

fn local_endpoint(variable: &str) -> String {
    let value =
        std::env::var(variable).unwrap_or_else(|_| panic!("local fixture endpoint required"));
    let url = reqwest::Url::parse(&value).unwrap_or_else(|_| panic!("invalid fixture URL"));
    assert_eq!(url.scheme(), "http");
    assert!(url
        .host_str()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback()));
    assert!(url.username().is_empty() && url.password().is_none() && url.query().is_none());
    value
}

fn config(uri: &str) -> CatalogConfig {
    // The cargo sandbox strips secret-looking env vars. A private fixture-only
    // file carries generated local credentials without weakening that filter.
    #[derive(serde::Deserialize)]
    struct FixtureAuth {
        access_key: String,
        secret_key: String,
    }
    let path = std::env::var("NANO_EXPORT_TEST_AUTH_FILE")
        .unwrap_or_else(|_| panic!("fixture auth file required"));
    let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("fixture auth file unavailable"));
    let auth: FixtureAuth =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("invalid fixture auth file"));
    CatalogConfig {
        uri: uri.to_string(),
        warehouse: "s3://export-fixture/".to_string(),
        credential: None,
        token_file: None,
        oauth_scope: None,
        oauth_audience: None,
        oauth_server_uri: None,
        realm: None,
        allow_anonymous: true,
        s3_endpoint: local_endpoint("NANO_EXPORT_TEST_S3_ENDPOINT"),
        s3_region: "us-east-1".to_string(),
        s3_access_key: auth.access_key,
        s3_secret_key: auth.secret_key,
        s3_session_token: None,
        s3_path_style_access: true,
        s3_default_credentials: false,
        vended_credentials: false,
    }
}

fn contract(extra: bool) -> SchemaContract {
    let mut fields = vec![
        Arc::new(NestedField::optional(
            1,
            "time",
            Type::Primitive(PrimitiveType::Long),
        )),
        Arc::new(NestedField::optional(
            2,
            "uid",
            Type::Primitive(PrimitiveType::String),
        )),
    ];
    if extra {
        fields.push(Arc::new(NestedField::optional(
            3,
            "message",
            Type::Primitive(PrimitiveType::String),
        )));
    }
    SchemaContract {
        version: 1,
        ocsf_version: if extra { "1.10.0" } else { "1.9.0" }.to_string(),
        schema: Schema::builder().with_fields(fields).build().unwrap(),
    }
}

fn parquet(uids: &[&str], extra: bool) -> Vec<u8> {
    let mut fields = vec![
        Field::new("time", DataType::Int64, true),
        Field::new("uid", DataType::Utf8, true),
    ];
    let mut arrays: Vec<Arc<dyn arrow_array::Array>> = vec![
        Arc::new(Int64Array::from(vec![1i64; uids.len()])),
        Arc::new(StringArray::from(uids.to_vec())),
    ];
    if extra {
        fields.push(Field::new("message", DataType::Utf8, true));
        arrays.push(Arc::new(StringArray::from(vec!["evolved"; uids.len()])));
    }
    let batch = RecordBatch::try_new(Arc::new(ArrowSchema::new(fields)), arrays).unwrap();
    let mut bytes = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut bytes, batch.schema(), None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    bytes
}

struct LocalFiles {
    io: FileIO,
    prefix: String,
    parts: BTreeMap<String, (Vec<u8>, u64)>,
}

#[async_trait::async_trait]
impl ExportTarget for LocalFiles {
    async fn prepare(
        &self,
        manifest: &ExportManifest,
        _schema: &Schema,
    ) -> Result<BTreeMap<String, Vec<DataFile>>> {
        let mut files = BTreeMap::new();
        for part in &manifest.add {
            let (bytes, rows) = self
                .parts
                .get(&part.part_id)
                .unwrap_or_else(|| panic!("unknown fixture part"));
            let path = format!("{}{}/data-00000.parquet", self.prefix, part.part_id);
            self.io
                .new_output(&path)?
                .write(bytes.clone().into())
                .await
                .map_err(|_| anyhow::anyhow!("fixture object write failed"))?;
            files.insert(
                part.part_id.clone(),
                vec![DataFileBuilder::default()
                    .content(DataContentType::Data)
                    .file_format(DataFileFormat::Parquet)
                    .file_path(path)
                    .partition(Struct::empty())
                    .partition_spec_id(0)
                    .record_count(*rows)
                    .file_size_in_bytes(bytes.len() as u64)
                    .build()?],
            );
        }
        Ok(files)
    }
}

fn manifest(
    at: i64,
    previous: Option<i64>,
    id: Option<&str>,
    rows: u64,
    bytes: u64,
    removed: &[&str],
) -> ExportManifest {
    ExportManifest {
        tenant_id: TENANT.to_string(),
        planned_at_ms: at,
        previous_plan_ms: previous,
        add: id
            .map(|id| ExportFile {
                part_id: id.to_string(),
                keys: vec![format!(
                    "{PARTS_ROOT}/tenant={TENANT}/parts/H/2026/01/01/00/{id}/data-00000.parquet"
                )],
                rows,
                bytes,
                min_time_us: 1,
                max_time_us: 1,
            })
            .into_iter()
            .collect(),
        remove_parts: removed.iter().map(|s| s.to_string()).collect(),
        hours: vec![ExportHour {
            event_hour: 0,
            parts: id.map(str::to_string).into_iter().collect(),
        }],
    }
}

fn settings(
    namespace: &str,
    location: &str,
    prefix: &str,
    contract: SchemaContract,
) -> ExportTable {
    ExportTable {
        tenant_id: TENANT.to_string(),
        namespace: namespace.to_string(),
        dataset: "events".to_string(),
        location: location.to_string(),
        data_prefix: prefix.to_string(),
        contract,
        max_files: 100,
    }
}

async fn read(table: &Table) -> Vec<RecordBatch> {
    table
        .scan()
        .build()
        .unwrap()
        .to_arrow()
        .await
        .unwrap_or_else(|_| panic!("fixture scan failed"))
        .try_collect()
        .await
        .unwrap_or_else(|_| panic!("fixture read failed"))
}

async fn uids(table: &Table) -> Vec<String> {
    let mut out = Vec::new();
    for batch in read(table).await {
        let column = batch
            .column_by_name("uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for row in 0..column.len() {
            out.push(column.value(row).to_string());
        }
    }
    out.sort();
    out
}

#[derive(Clone)]
struct Proxy {
    upstream: String,
    lost_response: Arc<AtomicBool>,
    conflict: Arc<AtomicBool>,
    commits: Arc<AtomicUsize>,
    oauth: Arc<AtomicUsize>,
}

async fn proxy(State(state): State<Proxy>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    if path == "/v1/oauth/tokens" {
        let token = format!(
            "fixture-token-{:064}",
            state.oauth.fetch_add(1, Ordering::SeqCst)
        );
        return Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"access_token":token,"token_type":"Bearer","expires_in":3600})
                    .to_string(),
            ))
            .unwrap();
    }
    let commit = parts.method == "POST" && path.contains("/tables/");
    if commit && state.conflict.swap(false, Ordering::SeqCst) {
        return Response::builder()
            .status(StatusCode::CONFLICT)
            .body(Body::from("{}"))
            .unwrap();
    }
    let bytes = to_bytes(body, 1_048_576).await.unwrap();
    let uri = format!(
        "{}{}",
        state.upstream,
        parts
            .uri
            .path_and_query()
            .map(|s| s.as_str())
            .unwrap_or("/")
    );
    let upstream = reqwest::Client::new()
        .request(parts.method, uri)
        .body(bytes)
        .send()
        .await
        .unwrap_or_else(|_| panic!("local REST proxy failed"));
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let body = upstream
        .bytes()
        .await
        .unwrap_or_else(|_| panic!("local REST response failed"));
    // The catalog reaches MinIO inside the Docker network. The Rust reader uses
    // its loopback published port; update only the fixture FileIO endpoint.
    let body = if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) {
        if let Some(config) = value.get_mut("config").and_then(|v| v.as_object_mut()) {
            config.insert(
                "s3.endpoint".to_string(),
                serde_json::Value::String(local_endpoint("NANO_EXPORT_TEST_S3_ENDPOINT")),
            );
        }
        bytes::Bytes::from(serde_json::to_vec(&value).unwrap())
    } else {
        body
    };
    if commit && status.is_success() {
        state.commits.fetch_add(1, Ordering::SeqCst);
        if state.lost_response.swap(false, Ordering::SeqCst) {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("{}"))
                .unwrap();
        }
    }
    let mut response = Response::builder().status(status);
    if let Some(value) = headers.get("content-type") {
        response = response.header("content-type", value);
    }
    response.body(Body::from(body)).unwrap()
}

#[tokio::test]
#[ignore = "requires isolated MinIO and Iceberg REST fixture; see fixtures/lean-iceberg-export/README.md"]
async fn rest_minio_readback_replay_overwrite_evolution_and_erasure() {
    let upstream = local_endpoint("NANO_EXPORT_TEST_CATALOG_URI");
    let state = Proxy {
        upstream: upstream.clone(),
        lost_response: Arc::new(AtomicBool::new(true)),
        conflict: Arc::new(AtomicBool::new(false)),
        commits: Arc::new(AtomicUsize::new(0)),
        oauth: Arc::new(AtomicUsize::new(0)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_uri = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(any(proxy)).with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut cfg = config(&proxy_uri);
    // Synthetic fixture credential only: the proxy models expiring OAuth sessions.
    cfg.credential = Some("fixture-client:fixture-only-synthetic-secret".to_string());
    cfg.allow_anonymous = false;
    cfg.oauth_server_uri = Some(format!("{proxy_uri}/v1/oauth/tokens"));
    let catalog = cfg
        .load()
        .await
        .unwrap_or_else(|_| panic!("fixture catalog session failed"));
    let namespace = format!("nano_test_{}", uuid::Uuid::new_v4().simple());
    let location = format!("s3://export-fixture/tenant={TENANT}/{namespace}/table");
    let prefix = format!("s3://export-fixture/tenant={TENANT}/{namespace}/parts/");
    let initial = contract(false);
    let id = initial.table_ident(&namespace, "events").unwrap();
    catalog
        .create_namespace(&id.namespace, HashMap::new())
        .await
        .unwrap_or_else(|_| panic!("fixture namespace failed"));
    let table = catalog
        .create_table(
            &id.namespace,
            TableCreation::builder()
                .name(id.name.clone())
                .location(location.clone())
                .schema(initial.schema.clone())
                .properties(initial.properties(TENANT))
                .build(),
        )
        .await
        .unwrap_or_else(|_| panic!("fixture table failed"));
    let hour_bytes = parquet(&["a"], false);
    let day_bytes = parquet(&["a", "b"], false);
    let erased_bytes = parquet(&["b"], true);
    let evolved_bytes = parquet(&["c"], true);
    let target = Arc::new(LocalFiles {
        io: table.file_io().clone(),
        prefix: prefix.clone(),
        parts: BTreeMap::from([
            (HOUR.to_string(), (hour_bytes.clone(), 1)),
            (DAY.to_string(), (day_bytes.clone(), 2)),
            (ERASED.to_string(), (erased_bytes.clone(), 1)),
            (EVOLVED.to_string(), (evolved_bytes.clone(), 1)),
        ]),
    });
    let committer = RestIcebergCommitter::new(
        cfg.clone(),
        settings(&namespace, &location, &prefix, initial),
        target.clone(),
    )
    .unwrap();
    let hour = manifest(1, None, Some(HOUR), 1, hour_bytes.len() as u64, &[]);
    committer
        .commit(&hour)
        .await
        .unwrap_or_else(|_| panic!("hour export failed"));
    assert_eq!(
        state.commits.load(Ordering::SeqCst),
        1,
        "lost success response must not double append"
    );
    let table = catalog
        .load_table(&id)
        .await
        .unwrap_or_else(|_| panic!("load hour failed"));
    let first_snapshot = table.metadata().current_snapshot_id();
    assert_eq!(uids(&table).await, vec!["a"]);
    committer
        .commit(&hour)
        .await
        .unwrap_or_else(|_| panic!("hour replay failed"));
    assert_eq!(
        catalog
            .load_table(&id)
            .await
            .unwrap_or_else(|_| panic!("reload failed"))
            .metadata()
            .current_snapshot_id(),
        first_snapshot
    );
    let day = manifest(2, Some(1), Some(DAY), 2, day_bytes.len() as u64, &[HOUR]);
    state.conflict.store(true, Ordering::SeqCst);
    committer
        .commit(&day)
        .await
        .unwrap_or_else(|_| panic!("day overwrite failed"));
    let table = catalog
        .load_table(&id)
        .await
        .unwrap_or_else(|_| panic!("load day failed"));
    assert_eq!(uids(&table).await, vec!["a", "b"]);
    assert_eq!(
        table
            .metadata()
            .current_snapshot()
            .unwrap()
            .summary()
            .operation,
        iceberg::spec::Operation::Overwrite
    );
    let evolved = RestIcebergCommitter::new(
        cfg.clone(),
        settings(&namespace, &location, &prefix, contract(true)),
        target.clone(),
    )
    .unwrap();
    let addition = manifest(
        3,
        Some(2),
        Some(EVOLVED),
        1,
        evolved_bytes.len() as u64,
        &[],
    );
    evolved
        .commit(&addition)
        .await
        .unwrap_or_else(|_| panic!("additive export failed"));
    let table = catalog
        .load_table(&id)
        .await
        .unwrap_or_else(|_| panic!("load additive export failed"));
    assert_eq!(uids(&table).await, vec!["a", "b", "c"]);
    let batches = read(&table).await;
    let nulls: usize = batches
        .iter()
        .map(|b| b.column_by_name("message").unwrap().null_count())
        .sum();
    assert_eq!(nulls, 2, "older Parquet reads new optional field as null");
    let erased = manifest(
        4,
        Some(3),
        Some(ERASED),
        1,
        erased_bytes.len() as u64,
        &[DAY, EVOLVED],
    );
    evolved
        .commit(&erased)
        .await
        .unwrap_or_else(|_| panic!("erasure/evolution export failed"));
    let table = catalog
        .load_table(&id)
        .await
        .unwrap_or_else(|_| panic!("load erasure failed"));
    assert_eq!(uids(&table).await, vec!["b"]);
    assert_eq!(table.metadata().properties()["nano.ocsf_version"], "1.10.0");
    assert_eq!(
        table
            .metadata()
            .current_schema()
            .field_by_name("uid")
            .unwrap()
            .id,
        2
    );
    assert!(
        table
            .metadata()
            .current_schema()
            .field_by_name("message")
            .unwrap()
            .id
            > 2
    );
    let batches = read(&table).await;
    assert_eq!(
        batches[0]
            .column_by_name("message")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0),
        "evolved"
    );
    committer
        .commit(&hour)
        .await
        .unwrap_or_else(|_| panic!("stale replay failed"));
    assert_eq!(
        uids(
            &catalog
                .load_table(&id)
                .await
                .unwrap_or_else(|_| panic!("load stale failed"))
        )
        .await,
        vec!["b"]
    );
    let mut cross_tenant = erased.clone();
    cross_tenant.tenant_id = uuid::Uuid::new_v4().to_string();
    assert!(evolved.commit(&cross_tenant).await.is_err());
    let empty = manifest(5, Some(4), None, 0, 0, &[ERASED]);
    evolved
        .commit(&empty)
        .await
        .unwrap_or_else(|_| panic!("full erasure failed"));
    assert!(uids(
        &catalog
            .load_table(&id)
            .await
            .unwrap_or_else(|_| panic!("load empty failed"))
    )
    .await
    .is_empty());
    assert!(
        state.oauth.load(Ordering::SeqCst) >= 6,
        "sessions must acquire fresh tokens across runs/retries"
    );
    // Freeze v1 explicitly, then create the isolated breaking v2 table.
    let table = catalog
        .load_table(&id)
        .await
        .unwrap_or_else(|_| panic!("load freeze failed"));
    let client = RestTableCommitClient::new(&cfg, &id)
        .await
        .unwrap_or_else(|_| panic!("fixture freeze client failed"));
    client
        .commit(
            vec![iceberg::TableRequirement::UuidMatch {
                uuid: table.metadata().uuid(),
            }],
            vec![iceberg::TableUpdate::SetProperties {
                updates: HashMap::from([(FROZEN.to_string(), "true".to_string())]),
            }],
        )
        .await
        .unwrap_or_else(|_| panic!("freeze failed"));
    assert!(evolved
        .commit(&manifest(
            6,
            Some(5),
            Some(ERASED),
            1,
            erased_bytes.len() as u64,
            &[]
        ))
        .await
        .is_err());
    let mut version2 = contract(true);
    version2.version = 2;
    let id2 = version2.table_ident(&namespace, "events").unwrap();
    assert_ne!(id2, id);
    let v2_location = format!("{location}_v2");
    let v2 = RestIcebergCommitter::new(
        cfg,
        settings(&namespace, &v2_location, &prefix, version2),
        target,
    )
    .unwrap();
    v2.commit(&manifest(
        1,
        None,
        Some(ERASED),
        1,
        erased_bytes.len() as u64,
        &[],
    ))
    .await
    .unwrap_or_else(|_| panic!("v2 export failed"));
    assert_eq!(
        uids(
            &catalog
                .load_table(&id2)
                .await
                .unwrap_or_else(|_| panic!("load v2 failed"))
        )
        .await,
        vec!["b"]
    );
    assert!(uids(
        &catalog
            .load_table(&id)
            .await
            .unwrap_or_else(|_| panic!("load frozen failed"))
    )
    .await
    .is_empty());
    server.abort();
}

/// Real customer adapter: owner-signed source, immutable copy into MinIO,
/// source retirement, replay, day replacement and full erasure read-back.
#[tokio::test]
#[ignore = "requires isolated MinIO and Iceberg REST fixture"]
async fn customer_signed_copy_survives_source_gc_and_erasure() {
    use ed25519_dalek::SigningKey;
    use nanosiem_lake_worker::{
        part_ingest::{
            iceberg_export::customer::CustomerExportTarget,
            s3_store::{S3Location, S3ObjectStore},
        },
        parts::{
            format::{PartId, PartKeys},
            levels::Level,
            part_log::{LocalObjectStore, ObjectStore},
            provenance::*,
        },
    };
    let cfg = config(&local_endpoint("NANO_EXPORT_TEST_CATALOG_URI"));
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(LocalObjectStore::new(directory.path().join("source")).unwrap());
    let location = format!("s3://export-fixture/customer/tenant={TENANT}/events_v1");
    let prefix = format!("{location}/data/");
    let destination = Arc::new(
        S3ObjectStore::new(&S3Location {
            endpoint: cfg.s3_endpoint.clone(),
            region: cfg.s3_region.clone(),
            bucket: "export-fixture".into(),
            prefix: format!("customer/tenant={TENANT}/events_v1/data/"),
            access_key_id: cfg.s3_access_key.clone(),
            secret_access_key: cfg.s3_secret_key.clone(),
            session_token: None,
        })
        .unwrap(),
    );
    let signer =
        LocalPartSigner::new("fixture-owner-key", SigningKey::from_bytes(&[9; 32])).unwrap();
    let target = Arc::new(
        CustomerExportTarget::new(
            TENANT.into(),
            source.clone(),
            destination.clone(),
            signer.trusted(),
            prefix.clone(),
        )
        .unwrap(),
    );
    let mut hour = None;
    for (at, previous, id, level, removed, rows) in [
        (1000, None, HOUR, Level::Hour, vec![], vec!["a", "b"]),
        (
            2000,
            Some(1000),
            DAY,
            Level::Day,
            vec![HOUR],
            vec!["a", "b", "c"],
        ),
        (3000, Some(2000), ERASED, Level::Hour, vec![DAY], vec!["c"]),
    ] {
        let body = parquet(&rows, false);
        let zero = "0".repeat(64);
        let record = ProvenanceRecord {
            format: PROVENANCE_FORMAT.into(),
            signer_key_id: "fixture-owner-key".into(),
            tenant_id: TENANT.into(),
            part_id: PartId::parse(id).unwrap(),
            level,
            created_at_ms: at,
            event_hour: 0,
            event_day: (level == Level::Day).then_some(0),
            rows: rows.len() as u64,
            min_time_us: 1,
            max_time_us: 1,
            schema_fingerprint: zero.clone(),
            merkle_root: zero.clone(),
            hours: vec![HourDigest {
                event_hour: 0,
                rows: rows.len() as u64,
                min_time_us: 1,
                max_time_us: 1,
                merkle_root: zero.clone(),
            }],
            files: PartFiles {
                data: vec![DataFileDigest {
                    name: "data-00000.parquet".into(),
                    bytes: body.len() as u64,
                    sha256: nanosiem_lake_worker::parts::sha256_hex(&body),
                    rows: rows.len() as u64,
                    row_groups: 1,
                    min_time_us: 1,
                    max_time_us: 1,
                    log_sources: None,
                    uid_blooms: None,
                    entity_blooms: None,
                    parquet_ranges: None,
                    entity_locators: None,
                    class_id: None,
                    tokens: FileDigest {
                        name: "tokens-00000.nti".into(),
                        bytes: 1,
                        sha256: zero.clone(),
                    },
                }],
                partials: vec![],
            },
            inputs: PartInputs::Parts {
                parts: vec![InputPart {
                    part_id: PartId::new(1).unwrap(),
                    level: Level::L0,
                    provenance_sha256: zero.clone(),
                    rows: rows.len() as u64,
                    merkle_root: zero.clone(),
                }],
            },
            admission: None,
            lowercased_at_rest: vec![],
            dedup: DedupStats {
                rows_in: rows.len() as u64,
                duplicates_dropped: 0,
                window: nanosiem_lake_worker::parts::DedupWindow::Exact,
            },
            writer: WriterInfo {
                role: "ingest".into(),
                build: "fixture".into(),
            },
        };
        let signature = signer
            .sign(TENANT, std::slice::from_ref(&record))
            .await
            .unwrap()
            .remove(0);
        let signed =
            SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap();
        let keys = PartKeys::new(TENANT, level, 0, &record.part_id).unwrap();
        source
            .put(&keys.provenance(), &signed.to_bytes().unwrap())
            .await
            .unwrap();
        source.put(&keys.data(0), &body).await.unwrap();
        let mut plan = manifest(
            at,
            previous,
            Some(id),
            rows.len() as u64,
            body.len() as u64,
            &removed,
        );
        plan.add[0].keys = vec![keys.data(0)];
        let committer = RestIcebergCommitter::new(
            cfg.clone(),
            settings("customer_export", &location, &prefix, contract(false)),
            target.clone(),
        )
        .unwrap();
        // Equivalent to the runner's custody-before-PG-plan publication.
        target
            .prepare(&plan, &contract(false).schema)
            .await
            .unwrap();
        let retry = directory.path().join("retry.parquet");
        std::fs::write(&retry, &body).unwrap();
        assert!(
            !destination
                .put_export_file_if_absent(
                    &format!("{id}/data-00000.parquet"),
                    &retry,
                    &nanosiem_lake_worker::parts::sha256_hex(&body),
                    body.len() as u64,
                    &nanosiem_lake_worker::parts::part_log::WriteHints {
                        class: nanosiem_lake_worker::parts::part_log::WriterClass::LakePart,
                        event_hour: 0,
                        min_time_ms: 0,
                        max_time_ms: 0
                    },
                )
                .await
                .unwrap(),
            "real S3 conditional PUT must preserve existing files"
        );
        source.delete(&keys.data(0)).await.unwrap();
        source.delete(&keys.provenance()).await.unwrap();
        committer.commit(&plan).await.unwrap();
        let copied = target.bytes_copied.load(Ordering::Relaxed);
        committer.commit(&plan).await.unwrap();
        assert_eq!(target.bytes_copied.load(Ordering::Relaxed), copied);
        let catalog = cfg.load().await.unwrap();
        let table = catalog.load_table(committer.table_id()).await.unwrap();
        assert_eq!(uids(&table).await, rows);
        hour = Some(plan);
    }
    let committer = RestIcebergCommitter::new(
        cfg.clone(),
        settings("customer_export", &location, &prefix, contract(false)),
        target.clone(),
    )
    .unwrap();
    let erased = manifest(
        4000,
        Some(hour.unwrap().planned_at_ms),
        None,
        0,
        0,
        &[ERASED],
    );
    committer.commit(&erased).await.unwrap();
    let catalog = cfg.load().await.unwrap();
    assert!(
        uids(&catalog.load_table(committer.table_id()).await.unwrap())
            .await
            .is_empty()
    );
    let mut foreign = erased;
    foreign.tenant_id = "00000000-0000-0000-0000-000000000002".into();
    assert!(committer.commit(&foreign).await.is_err());
}
