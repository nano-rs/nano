// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use arrow_json::reader::{infer_json_schema_from_seekable, ReaderBuilder};
use serde_json::json;
use std::io::{Cursor, Write};
use std::sync::Mutex;

const TENANT: &str = "tenant-a";
const SOURCE: &str = "0b8f6c1e-3c55-4a8e-9d3e-2f7c1a4b5d60";
const CREDENTIAL: &str = "1b84f015-b560-433b-8bb6-ed4e39f48334";

fn source() -> LandingSource {
    LandingSource {
        source_id: Uuid::parse_str(SOURCE).unwrap(),
        route_key: "tenzir_sysmon".into(),
        credential_id: Uuid::parse_str(CREDENTIAL).unwrap(),
        active: true,
    }
}

fn key(name: &str) -> String {
    format!("{LANDING_PREFIX}tenant_id={TENANT}/source={SOURCE}/{name}")
}

/// A Sysmon EID 1 mapped to OCSF 1.9 Process Activity, as Tenzir sends it.
fn sysmon(uid: Option<&str>, pid: i64) -> Value {
    let mut event = json!({
        "class_uid": 1007, "class_name": "Process Activity",
        "category_uid": 1, "category_name": "System Activity",
        "activity_id": 1, "activity_name": "Launch", "type_uid": 100701,
        "severity_id": 1, "severity": "Informational",
        "time": 1_791_975_595_105_i64,
        "message": "Process launched",
        "raw_data": "{\"EventID\":1}",
        "metadata": {
            "version": "1.9.0", "log_source": "spoofed", "tenant_uid": "other-tenant",
            "product": {"name": "Sysmon", "vendor_name": "Microsoft"}
        },
        "device": {"hostname": "wks-01", "type_id": 0},
        "actor": {"process": {"pid": 900, "name": "explorer.exe"}},
        "process": {"pid": pid, "cmd_line": "cmd.exe /c echo x"}
    });
    if let Some(uid) = uid {
        event["metadata"]["uid"] = json!(uid);
    }
    event
}

fn ndjson(events: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for event in events {
        serde_json::to_writer(&mut out, event).unwrap();
        out.push(b'\n');
    }
    out
}

/// Typed nested Parquet, the shape Tenzir's `write_parquet` produces.
fn parquet(events: &[Value]) -> Vec<u8> {
    let json = ndjson(events);
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let schema = Arc::new(schema);
    let reader = ReaderBuilder::new(schema.clone()).build(Cursor::new(json)).unwrap();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, schema, None).unwrap();
    for batch in reader {
        writer.write(&batch.unwrap()).unwrap();
    }
    writer.close().unwrap();
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn stage() -> LandingOcsfStage {
    LandingOcsfStage::new(1).unwrap()
}

fn events_of(converted: &Converted) -> Vec<Value> {
    converted
        .objects
        .iter()
        .flat_map(|(_, bytes, _)| decode_bronze(bytes).unwrap())
        .map(Result::unwrap)
        .collect()
}

#[test]
fn keys_parse_to_their_source_and_format() {
    let parsed = parse_key(&key("2026/10/14/a.parquet"), TENANT).unwrap();
    assert_eq!(parsed.source_id, Uuid::parse_str(SOURCE).unwrap());
    assert_eq!(parsed.format, FileFormat::Parquet);
    assert_eq!(parse_key(&key("a.ndjson.gz"), TENANT).unwrap().format, FileFormat::Ndjson { gzip: true });
    assert_eq!(parse_key(&key("a.jsonl"), TENANT).unwrap().format, FileFormat::Ndjson { gzip: false });
    assert_eq!(parse_key(&key("a.csv"), TENANT), Err("format_unsupported"));
    assert_eq!(parse_key(&key("x/../a.parquet"), TENANT), Err("key_malformed"));
    assert_eq!(parse_key(&key("a.parquet"), "tenant-b"), Err("tenant_mismatch"));
    let upper = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={}/a.parquet", SOURCE.to_uppercase());
    assert_eq!(parse_key(&upper, TENANT), Err("source_malformed"));
    assert_eq!(parse_key("bronze-v2/tenant_id=tenant-a/a.parquet", TENANT), Err("key_outside_landing"));
    assert_eq!(refused_key(&key("a.parquet")), format!("{REFUSED_PREFIX}tenant_id={TENANT}/source={SOURCE}/a.parquet"));
}

#[test]
fn typed_parquet_becomes_bronze_that_admission_admits() {
    let file = parquet(&[sysmon(Some("sysmon:wks-01:1"), 1), sysmon(Some("sysmon:wks-01:2"), 2)]);
    let converted = convert_file(&file, FileFormat::Parquet, &stage(), TENANT, &source(), Utc::now()).unwrap();
    assert_eq!((converted.rows_accepted, converted.rows_refused), (2, 0));
    assert_eq!(converted.objects.len(), 1);
    let (bronze_key, bytes, rows) = &converted.objects[0];
    assert!(bronze_key.starts_with(&format!("{BRONZE_PREFIX}tenant_id={TENANT}/")), "{bronze_key}");
    assert!(bronze_key.ends_with(".parquet"));
    assert_eq!(*rows, 2);
    for event in events_of(&converted) {
        let metadata = &event["metadata"];
        assert_eq!(metadata["log_source"], "tenzir_sysmon", "the folder decides the source");
        assert_eq!(metadata["tenant_uid"], TENANT);
        assert_eq!(metadata["nano_credential_id"], CREDENTIAL);
        assert_eq!(metadata["ingress_transport"], "landing_bucket");
        assert!(metadata["uid"].as_str().unwrap().starts_with("sysmon:wks-01:"), "sender uid kept");
        assert_eq!(event["class_uid"], 1007);
    }

    // The written object goes through the exact admission Vector's files do.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("landed.parquet");
    std::fs::write(&path, bytes).unwrap();
    let admitted = crate::bronze::admit_bronze_files(&[path], TENANT).unwrap();
    assert_eq!(admitted.source_rows, 2);
    assert_eq!(admitted.batch.len(), 2);
    for row in admitted.batch.rows() {
        assert_eq!(row.ocsf_event["metadata"]["ingress_transport"], "landing_bucket");
        assert_eq!(row.ocsf_event["class_uid"], 1007);
    }
}

#[test]
fn rfc3339_time_strings_keep_the_event_time() {
    let mut event = sysmon(Some("sysmon:wks-01:9"), 9);
    event["time"] = json!("2026-10-14T12:00:00.250Z");
    let converted = convert_file(&ndjson(&[event]), FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), Utc::now()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("t.parquet");
    std::fs::write(&path, &converted.objects[0].1).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap().build().unwrap();
    let batch = reader.into_iter().next().unwrap().unwrap();
    let times = batch.column_by_name(BRONZE_TIME_COLUMN).unwrap().as_any().downcast_ref::<TimestampMicrosecondArray>().unwrap();
    assert_eq!(times.value(0), DateTime::parse_from_rfc3339("2026-10-14T12:00:00.250Z").unwrap().timestamp_micros());
}

#[test]
fn bad_rows_are_counted_and_good_rows_go_on() {
    let mut body = ndjson(&[sysmon(Some("sysmon:wks-01:3"), 3)]);
    body.extend_from_slice(b"not json\n[1,2]\n");
    body.extend_from_slice(&ndjson(&[json!({"class_uid": 1007, "metadata": {"version": "1.9.0"}})]));
    let converted = convert_file(&gzip(&body), FileFormat::Ndjson { gzip: true }, &stage(), TENANT, &source(), Utc::now()).unwrap();
    assert_eq!(converted.rows_accepted, 1);
    assert_eq!(converted.rows_refused, 3);
    assert_eq!(converted.first_refusal.as_ref().unwrap().reason, "event_not_object");
}

#[test]
fn a_file_with_nothing_admissible_is_refused_whole() {
    let refusal = |bytes: &[u8], format| convert_file(bytes, format, &stage(), TENANT, &source(), Utc::now()).unwrap_err().reason;
    assert_eq!(refusal(b"PAR1 definitely not parquet", FileFormat::Parquet), "parquet_unreadable");
    assert_eq!(refusal(b"\n\n", FileFormat::Ndjson { gzip: false }), "no_rows");
    assert_eq!(refusal(b"not gzip", FileFormat::Ndjson { gzip: true }), "ndjson_unreadable");
    assert_eq!(refusal(b"garbage\n", FileFormat::Ndjson { gzip: false }), "event_not_object");
}

#[test]
fn the_row_cap_refuses_the_file() {
    let mut body = Vec::with_capacity((MAX_LANDING_ROWS + 1) * 3);
    for _ in 0..=MAX_LANDING_ROWS {
        body.extend_from_slice(b"{}\n");
    }
    assert_eq!(read_rows(&body, FileFormat::Ndjson { gzip: false }).unwrap_err().reason, "too_many_rows");
}

#[test]
fn rows_without_a_uid_get_the_same_uid_on_every_conversion() {
    let file = ndjson(&[sysmon(None, 4), sysmon(None, 4)]);
    let uids = |converted: Converted| events_of(&converted).iter().map(|e| e["metadata"]["uid"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    let first = uids(convert_file(&file, FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), Utc::now()).unwrap());
    let again = uids(convert_file(&file, FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), Utc::now()).unwrap());
    assert_eq!(first, again);
    assert_ne!(first[0], first[1], "identical rows at different ordinals stay distinct");
}

#[test]
fn the_source_policy_allows_put_into_its_own_folder_only() {
    let policy = source_policy("nano-lake", TENANT, Uuid::parse_str(SOURCE).unwrap());
    let statement = &policy["Statement"][0];
    assert_eq!(statement["Action"], json!(["s3:PutObject"]));
    assert_eq!(statement["Effect"], "Allow");
    assert_eq!(
        statement["Resource"],
        json!([format!("arn:aws:s3:::nano-lake/{LANDING_PREFIX}tenant_id={TENANT}/source={SOURCE}/*")])
    );
    assert_eq!(policy["Statement"].as_array().unwrap().len(), 1);
}

#[derive(Default)]
struct MemoryLedger {
    sources: Vec<LandingSource>,
    files: Mutex<Vec<(String, String, String, Option<String>)>>, // key, etag, state, reason
}

#[async_trait]
impl Ledger for MemoryLedger {
    async fn source(&self, source_id: Uuid) -> Result<Option<LandingSource>> {
        Ok(self.sources.iter().find(|s| s.source_id == source_id).cloned())
    }
    async fn claim(&self, key: &str, etag: &str, _size: u64, _source_id: Option<Uuid>) -> Result<Claim> {
        let mut files = self.files.lock().unwrap();
        if let Some((id, file)) = files.iter().enumerate().find(|(_, f)| f.0 == key && f.1 == etag) {
            return Ok(if file.2 == "claimed" { Claim::Leased } else { Claim::Finished { id: id as i64 } });
        }
        files.push((key.into(), etag.into(), "claimed".into(), None));
        Ok(Claim::Owned { id: files.len() as i64 - 1, attempt: 1 })
    }
    async fn accepted(&self, id: i64, converted: &Converted, _bronze_keys: &str) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        files[id as usize].2 = "accepted".into();
        files[id as usize].3 = converted.first_refusal.as_ref().map(|r| r.reason.to_string());
        Ok(())
    }
    async fn refused(&self, id: i64, reason: &str, _rows: u64, _sha: Option<&str>) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        files[id as usize].2 = "refused".into();
        files[id as usize].3 = Some(reason.into());
        Ok(())
    }
    async fn redelivered(&self, _id: i64) -> Result<()> {
        Ok(())
    }
}

async fn keys_under(store: &Operator, prefix: &str) -> Vec<String> {
    let mut keys = store
        .list_with(prefix)
        .recursive(true)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|entry| entry.path().to_string())
        .filter(|path| !path.ends_with('/'))
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

#[tokio::test]
async fn the_converter_accepts_refuses_and_drops_redeliveries_without_wedging() {
    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let revoked = Uuid::new_v4();
    let converter = Converter {
        store: store.clone(),
        ledger: MemoryLedger {
            sources: vec![
                source(),
                LandingSource { source_id: revoked, route_key: "old".into(), credential_id: Uuid::new_v4(), active: false },
            ],
            ..Default::default()
        },
        stage: stage(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 100,
    };
    let good = parquet(&[sysmon(Some("sysmon:wks-01:5"), 5)]);
    store.write(&key("a/good.parquet"), good.clone()).await.unwrap();
    store.write(&key("b/bad.parquet"), b"nope".to_vec()).await.unwrap();
    let unknown = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={}/x.ndjson", Uuid::new_v4());
    store.write(&unknown, ndjson(&[sysmon(Some("u"), 1)])).await.unwrap();
    let revoked_key = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={revoked}/x.ndjson");
    store.write(&revoked_key, ndjson(&[sysmon(Some("r"), 1)])).await.unwrap();

    let report = converter.tick().await.unwrap();
    assert_eq!((report.listed, report.accepted, report.refused, report.failed), (4, 1, 3, 0), "{report:?}");
    assert!(keys_under(&store, LANDING_PREFIX).await.is_empty(), "every landed file is finished");
    let bronze = keys_under(&store, BRONZE_PREFIX).await;
    assert_eq!(bronze.len(), 1);
    let refused = keys_under(&store, REFUSED_PREFIX).await;
    assert_eq!(refused.len(), 3);
    assert!(refused.contains(&refused_key(&key("b/bad.parquet"))));
    let reasons = converter.ledger.files.lock().unwrap().iter().filter_map(|f| f.3.clone()).collect::<Vec<_>>();
    assert!(reasons.contains(&"parquet_unreadable".to_string()));
    assert!(reasons.contains(&"source_unknown".to_string()));
    assert!(reasons.contains(&"source_revoked".to_string()));

    // The same object again (same key, same content): deleted, not reconverted.
    store.write(&key("a/good.parquet"), good).await.unwrap();
    let report = converter.tick().await.unwrap();
    assert_eq!((report.listed, report.redelivered, report.accepted), (1, 1, 0), "{report:?}");
    assert!(keys_under(&store, LANDING_PREFIX).await.is_empty());
    assert_eq!(keys_under(&store, BRONZE_PREFIX).await.len(), 1);

    // An empty tick is a no-op.
    assert_eq!(converter.tick().await.unwrap(), TickReport::default());
}


/// Change 1 (NAN-3807): `landing_bucket` is a new closed-list lane value. The
/// only open-core reader of the closed list is bronze admission in
/// `lake_part_ingest` (installed as `nanosiem-lake-ingest`). The open cell
/// image builds the converter and that reader in ONE cargo invocation from
/// one source tree, so no open-core image can ship a converter that stamps
/// `landing_bucket` next to an admitter that only knows the older values.
#[test]
fn the_open_cell_image_builds_the_converter_with_its_admitter() {
    let dockerfile = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Dockerfile")).unwrap();
    let stage = dockerfile
        // NAN-4304: match the stage by name, not its base image (NAN-3901
        // rebased it from `chef` onto the shared `builder` stage).
        .split(" AS open-lake-cell-builder\n")
        .nth(1)
        .and_then(|rest| rest.split("\nFROM ").next())
        .expect("open-lake-cell-builder stage");
    let build = stage
        .split("cargo build --release --locked -p nanosiem-lake-worker")
        .nth(1)
        .and_then(|rest| rest.split("&&").next())
        .expect("one lake-worker cargo build");
    assert!(build.contains("--bin lake_part_ingest"), "{build}");
    assert!(build.contains("--bin lake_landing_ingest"), "{build}");
    assert!(stage.contains("target/release/lake_landing_ingest"), "the converter is installed");
    // And the admitter accepts the lane the converter stamps.
    assert!(crate::iceberg::is_platform_ingress_transport(
        nanosiem_core::parsers::landing_ocsf::LANDING_INGRESS_TRANSPORT
    ));
}

/// Records removals; refuses the users named in `fail`.
struct FakeRemover {
    removed: Mutex<Vec<(String, Uuid)>>,
    fail: Vec<String>,
}

#[async_trait]
impl CredentialRemover for FakeRemover {
    async fn remove(&self, object_user: &str, source_id: Uuid) -> Result<()> {
        if self.fail.iter().any(|user| user == object_user) {
            anyhow::bail!("object store unavailable");
        }
        self.removed.lock().unwrap().push((object_user.to_string(), source_id));
        Ok(())
    }
}

/// DB-backed: a disposable PostgreSQL at NANOSIEM_TEST_DATABASE_URL; the test
/// works in a throwaway schema with a minimal `log_sources` and migration 364.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn deleting_a_log_source_revokes_its_landing_source_and_key() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
    let schema = format!("nan3807_{}", Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect({
            let schema = schema.clone();
            move |conn, _| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str()).await.map(|_| ())
                })
            }
        })
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY);"))
        .execute(&pool)
        .await
        .expect("setup");
    sqlx::raw_sql(include_str!("../../migrations/postgres/364_landing_ocsf.sql")).execute(&pool).await.expect("364");

    let (deleted, kept, revoked, stuck) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(4));
    for (id, state) in [(deleted, "active"), (kept, "active"), (revoked, "revoked"), (stuck, "active")] {
        sqlx::query("INSERT INTO log_sources (id) VALUES ($1)").bind(id).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO landing_sources (source_id, route_key, credential_id, object_user, state) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(format!("route_{}", id.as_u128()))
        .bind(Uuid::new_v4())
        .bind(format!("nluser{}", id.as_u128()))
        .bind(state)
        .execute(&pool)
        .await
        .unwrap();
    }
    // A finished file of the source keeps its history after the revoke.
    sqlx::query(
        "INSERT INTO landing_files (object_key, etag, source_id, size_bytes, state, finished_at) \
         VALUES ('k', 'e', $1, 1, 'accepted', NOW())",
    )
    .bind(deleted)
    .execute(&pool)
    .await
    .unwrap();
    let ledger = PgLedger { pool: pool.clone(), lease: std::time::Duration::from_secs(60) };
    assert!(ledger.source(deleted).await.unwrap().unwrap().active);

    sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)")
        .bind(vec![deleted, revoked, stuck])
        .execute(&pool)
        .await
        .unwrap();
    // Intake stops at once, before any sweep.
    assert!(!ledger.source(deleted).await.unwrap().unwrap().active);
    assert!(ledger.source(kept).await.unwrap().unwrap().active);

    let remover = FakeRemover { removed: Mutex::new(Vec::new()), fail: vec![format!("nluser{}", stuck.as_u128())] };
    let swept = ledger.revoke_orphans(&remover).await.unwrap();
    assert_eq!(swept, vec![deleted, revoked]);
    // The active orphan's key is deleted; the already-revoked one has none left.
    assert_eq!(*remover.removed.lock().unwrap(), vec![(format!("nluser{}", deleted.as_u128()), deleted)]);
    assert!(ledger.source(deleted).await.unwrap().is_none(), "no landing row once its key is gone");
    assert!(ledger.source(revoked).await.unwrap().is_none());
    assert!(ledger.source(kept).await.unwrap().is_some());
    // A removal that failed keeps the row (and its key) for the next sweep.
    assert!(ledger.source(stuck).await.unwrap().is_some());
    let file_source: Option<Uuid> = sqlx::query_scalar("SELECT source_id FROM landing_files WHERE object_key = 'k'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(file_source, None);

    let retry = FakeRemover { removed: Mutex::new(Vec::new()), fail: Vec::new() };
    assert_eq!(ledger.revoke_orphans(&retry).await.unwrap(), vec![stuck]);
    assert!(ledger.orphaned_sources().await.unwrap().is_empty());

    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&pool).await.unwrap();
}

// --- Tenzir Arrow extension types (NAN-4301) ---

/// Real Tenzir 6.19.1 `ocsf_derive | ocsf_cast | to_s3 { write_parquet }`
/// output (OCSF 1.9 Authentication): `src_endpoint.ip` / `dst_endpoint.ip`
/// are `tenzir.ip` (FixedSizeBinary(16), IPv4-mapped).
const TENZIR_AUTH_PARQUET: &[u8] = include_bytes!("../tests/fixtures/tenzir-6.19.1-ocsf-auth-ip.parquet");

fn tenzir_field(name: &str, data_type: DataType, extension: &str) -> Field {
    Field::new(name, data_type, true)
        .with_metadata(std::collections::HashMap::from([(EXTENSION_NAME.to_string(), extension.to_string())]))
}

fn tenzir_ip_field(name: &str) -> Field {
    tenzir_field(name, DataType::FixedSizeBinary(16), "tenzir.ip")
}

fn mapped(v4: [u8; 4]) -> [u8; 16] {
    std::net::Ipv4Addr::from(v4).to_ipv6_mapped().octets()
}

fn tenzir_ips(values: &[Option<[u8; 16]>]) -> ArrayRef {
    Arc::new(arrow_array::FixedSizeBinaryArray::try_from_sparse_iter_with_size(values.iter().map(|v| v.as_ref()), 16).unwrap())
}

fn json_rows(batch: RecordBatch) -> Vec<Value> {
    let batch = decode_tenzir_extensions(batch).unwrap();
    let mut writer = LineDelimitedWriter::new(Vec::new());
    writer.write(&batch).unwrap();
    writer.finish().unwrap();
    writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect()
}

#[test]
fn real_tenzir_parquet_with_ip_columns_converts_with_no_refusals() {
    let converted = convert_file(TENZIR_AUTH_PARQUET, FileFormat::Parquet, &stage(), TENANT, &source(), Utc::now()).unwrap();
    assert!(converted.rows_accepted > 0);
    assert_eq!(converted.rows_refused, 0, "first refusal: {:?}", converted.first_refusal);
    let events = events_of(&converted);
    assert_eq!(events.len() as u64, converted.rows_accepted);
    assert_eq!(events[0]["class_uid"], 3002);
    assert_eq!(events[0]["src_endpoint"]["ip"], "10.77.0.0");
    assert_eq!(events[0]["dst_endpoint"]["ip"], "10.0.0.5");
    for event in &events {
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let ip = event[endpoint]["ip"].as_str().unwrap();
            assert!(ip.parse::<std::net::IpAddr>().is_ok(), "{endpoint}.ip = {ip}");
        }
    }
}

#[test]
fn tenzir_ips_become_dotted_quad_or_canonical_ipv6_and_nulls_stay_null() {
    let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let schema = Arc::new(Schema::new(vec![tenzir_ip_field("ip"), Field::new("raw", DataType::FixedSizeBinary(16), true)]));
    let raw = tenzir_ips(&[Some(mapped([1, 2, 3, 4])), None, Some(v6.octets())]);
    let batch = RecordBatch::try_new(
        schema,
        vec![tenzir_ips(&[Some(mapped([10, 77, 0, 0])), None, Some(v6.octets())]), raw],
    )
    .unwrap();
    let rows = json_rows(batch);
    assert_eq!(rows[0]["ip"], "10.77.0.0");
    assert!(rows[1].get("ip").is_none(), "null stays null (omitted)");
    assert_eq!(rows[2]["ip"], "2001:db8::1");
    assert_ne!(rows[0]["raw"], "1.2.3.4", "untagged binary is not reinterpreted");
}

#[test]
fn tenzir_ips_inside_lists_and_maps_are_decoded() {
    use arrow_array::builder::{FixedSizeBinaryBuilder, ListBuilder, MapBuilder, StringBuilder, StructBuilder};
    // endpoints: list<struct<ip: tenzir.ip>>
    let ip = Arc::new(tenzir_ip_field("ip"));
    let item = Arc::new(Field::new("item", DataType::Struct(Fields::from(vec![ip.clone()])), true));
    let mut list = ListBuilder::new(StructBuilder::new(
        Fields::from(vec![ip.clone()]),
        vec![Box::new(FixedSizeBinaryBuilder::new(16)) as Box<dyn arrow_array::builder::ArrayBuilder>],
    ))
    .with_field(item.clone());
    for (value, end_of_row) in [
        (Some(mapped([192, 168, 1, 1])), false),
        (None, true),
        (Some("fe80::1".parse::<Ipv6Addr>().unwrap().octets()), true),
    ] {
        let ips = list.values().field_builder::<FixedSizeBinaryBuilder>(0).unwrap();
        match value {
            Some(bytes) => ips.append_value(bytes).unwrap(),
            None => ips.append_null(),
        }
        list.values().append(true);
        if end_of_row {
            list.append(true);
        }
    }
    let list = list.finish();
    // peers: map<utf8, tenzir.ip>
    let mut map = MapBuilder::new(None, StringBuilder::new(), FixedSizeBinaryBuilder::new(16))
        .with_values_field(Arc::new(tenzir_ip_field("value")));
    map.keys().append_value("gw");
    map.values().append_value(mapped([10, 0, 0, 1])).unwrap();
    map.append(true).unwrap();
    map.append(false).unwrap();
    let map = map.finish();
    // ips: list<tenzir.ip> (bare list of IPs)
    let mut bare = ListBuilder::new(FixedSizeBinaryBuilder::new(16)).with_field(Arc::new(tenzir_ip_field("item")));
    bare.values().append_value(mapped([8, 8, 8, 8])).unwrap();
    bare.values().append_null();
    bare.append(true);
    bare.append(false);
    let bare = bare.finish();

    let schema = Arc::new(Schema::new(vec![
        Field::new("endpoints", list.data_type().clone(), true),
        Field::new("peers", map.data_type().clone(), true),
        Field::new("ips", bare.data_type().clone(), true),
    ]));
    let batch = RecordBatch::try_new(schema, vec![Arc::new(list), Arc::new(map), Arc::new(bare)]).unwrap();
    let rows = json_rows(batch);
    assert_eq!(rows[0]["endpoints"], json!([{"ip": "192.168.1.1"}, {}]));
    assert_eq!(rows[1]["endpoints"], json!([{"ip": "fe80::1"}]));
    assert_eq!(rows[0]["peers"], json!({"gw": "10.0.0.1"}));
    assert!(rows[1].get("peers").is_none());
    assert_eq!(rows[0]["ips"], json!(["8.8.8.8", null]));
    assert!(rows[1].get("ips").is_none());
}

#[test]
fn tenzir_subnets_render_as_cidr_text() {
    let ip = Arc::new(tenzir_ip_field("address"));
    let children = Fields::from(vec![ip, Arc::new(Field::new("length", DataType::UInt8, true))]);
    let subnets = StructArray::try_new(
        children.clone(),
        vec![
            tenzir_ips(&[
                Some(mapped([10, 1, 2, 0])),
                Some("2001:db8::".parse::<Ipv6Addr>().unwrap().octets()),
                Some(mapped([18, 52, 0, 0])),
                None,
            ]),
            Arc::new(arrow_array::UInt8Array::from(vec![Some(120), Some(32), Some(80), Some(8)])),
        ],
        None,
    )
    .unwrap();
    let schema = Arc::new(Schema::new(vec![tenzir_field("net", DataType::Struct(children), "tenzir.subnet")]));
    let rows = json_rows(RecordBatch::try_new(schema, vec![Arc::new(subnets)]).unwrap());
    assert_eq!(rows[0]["net"], "10.1.2.0/24", "IPv4 length is stored +96");
    assert_eq!(rows[1]["net"], "2001:db8::/32");
    assert_eq!(rows[2]["net"], "::ffff:18.52.0.0/80", "a mapped address under /96 is an IPv6 network");
    assert!(rows[3].get("net").is_none());
}

#[test]
fn tenzir_extension_types_survive_a_parquet_round_trip_through_read_rows() {
    // ip + enumeration (string dictionary) written as Tenzir does, read the
    // way landing reads every Parquet file.
    let enum_type = DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8));
    let schema = Arc::new(Schema::new(vec![
        tenzir_ip_field("ip"),
        tenzir_field("status", enum_type, "tenzir.enumeration"),
    ]));
    let status: arrow_array::DictionaryArray<arrow_array::types::UInt8Type> = vec![Some("Success"), None].into_iter().collect();
    let batch = RecordBatch::try_new(schema.clone(), vec![tenzir_ips(&[Some(mapped([10, 0, 0, 5])), None]), Arc::new(status)]).unwrap();
    let mut file = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut file, schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let rows = read_rows(&file, FileFormat::Parquet).unwrap();
    assert_eq!(rows[0], json!({"ip": "10.0.0.5", "status": "Success"}));
    assert_eq!(rows[1], json!({}));
}

// --- Hive `class_uid=<N>` partition folders (NAN-4337) ---

#[test]
fn a_class_uid_folder_below_the_source_is_read_as_a_hive_partition() {
    let class = |name: &str| parse_key(&key(name), TENANT).map(|parsed| parsed.partition_class_uid);
    assert_eq!(class("class_uid=4003/events-1.parquet"), Ok(Some(4003)));
    assert_eq!(class("2026/10/21/class_uid=3002/x/events-1.parquet"), Ok(Some(3002)));
    assert_eq!(class("events-1.parquet"), Ok(None));
    // Only folders count: a file named like a partition is just a name.
    assert_eq!(class("class_uid=4003.parquet"), Ok(None));
    assert_eq!(class("not_class_uid=4003/a.parquet"), Ok(None));
    for junk in ["abc", "", "-1", "+4003", "4003 ", "4003.0", "0x0FA3", "1234567", "99999"] {
        assert_eq!(class(&format!("class_uid={junk}/a.parquet")), Err("class_uid_partition_invalid"), "{junk:?}");
    }
    // Base Event (0) is an OCSF class like any other.
    assert_eq!(class("class_uid=0/a.parquet"), Ok(Some(0)));
    assert_eq!(class("class_uid=4003/class_uid=4003/a.parquet"), Err("class_uid_partition_ambiguous"));
    assert_eq!(class("class_uid=4003/b/class_uid=3002/a.parquet"), Err("class_uid_partition_ambiguous"));
    // Confinement is unchanged: the folder never lets a key leave its source.
    assert_eq!(class("class_uid=4003/../a.parquet"), Err("key_malformed"));
    assert_eq!(class("class_uid=4003//a.parquet"), Err("key_malformed"));
    let tenant_level = format!("{LANDING_PREFIX}tenant_id={TENANT}/class_uid=4003/source={SOURCE}/a.parquet");
    assert_eq!(parse_key(&tenant_level, TENANT), Err("key_malformed"));
}

#[test]
fn rows_without_class_uid_take_the_partition_and_are_counted() {
    let mut no_class = sysmon(Some("np"), 7);
    no_class.as_object_mut().unwrap().remove("class_uid");
    let file = ndjson(&[no_class.clone(), sysmon(Some("wp"), 8)]);
    let converted = convert_landed(&file, FileFormat::Ndjson { gzip: false }, Some(1007), &stage(), TENANT, &source(), Utc::now())
        .unwrap();
    assert_eq!((converted.rows_accepted, converted.rows_refused, converted.rows_class_from_path), (2, 0, 1));
    // Without the partition the same file keeps only the row that has it.
    let plain = convert_file(&file, FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), Utc::now()).unwrap();
    assert_eq!((plain.rows_accepted, plain.rows_refused, plain.rows_class_from_path), (1, 1, 0));
    assert_eq!(plain.first_refusal.unwrap().reason, "ocsf_class_uid_missing_or_invalid");
}
