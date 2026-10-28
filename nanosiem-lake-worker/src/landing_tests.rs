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
            // Refused in place: never claimed again, never a (deleting) redelivery.
            return Ok(if file.2 == "claimed" || file.2 == "refused_in_place" {
                Claim::Leased
            } else {
                Claim::Finished { id: id as i64 }
            });
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
    async fn refused_in_place(&self, id: i64, reason: &str, _rows: u64, _sha: Option<&str>) -> Result<()> {
        let mut files = self.files.lock().unwrap();
        files[id as usize].2 = "refused_in_place".into();
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
        emit: BronzeObjects,
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
         VALUES ($2, 'e', $1, 1, 'accepted', NOW())",
    )
    .bind(deleted)
    .bind(format!("{LANDING_PREFIX}tenant_id={TENANT}/source={deleted}/k"))
    .execute(&pool)
    .await
    .unwrap();
    // Rows from before migration 374 carry no tenant: the install's
    // converter adopts them (one tenant on this database).
    sqlx::raw_sql(include_str!("../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&pool).await.expect("374");
    let ledger = PgLedger::new(pool.clone(), std::time::Duration::from_secs(60), TENANT);
    assert!(ledger.source(deleted).await.unwrap().is_none(), "an unadopted source is unknown to every tenant");
    assert_eq!(ledger.adopt_legacy_rows().await.unwrap(), (1, 4));
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
    let file_source: Option<Uuid> = sqlx::query_scalar("SELECT source_id FROM landing_files WHERE object_key LIKE '%/k'")
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

// --- Sovereign `--tenzir` HA: N converters on one ledger (NAN-4629) ---

/// A sovereign tenant id (UUID), as the installer assigns it.
const HA_TENANT: &str = "6a1c2f0e-1b7d-4c55-9c1e-2f3a4b5c6d7e";
/// Active-active converters, one per node. Deliberately not 4: nothing in the
/// claim path may assume the minimum host count.
const HA_NODES: usize = 5;

fn ha_key(source: Uuid, name: &str) -> String {
    format!("{LANDING_PREFIX}tenant_id={HA_TENANT}/source={source}/{name}")
}

/// A pool on its own throwaway schema. One pool per converter: each node has
/// its own connections to the shared (Patroni) database.
async fn ha_pool(url: &str, schema: &str) -> sqlx::PgPool {
    let schema = schema.to_string();
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _| {
            let schema = schema.clone();
            Box::pin(async move {
                sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str()).await.map(|_| ())
            })
        })
        .connect(url)
        .await
        .expect("connect")
}

/// NAN-4629 production path for the sovereign Tenzir model: the UNCHANGED
/// open-core bucket drop (`Converter` = `PrefixDiscover` + `PgLedger` +
/// `BronzeObjects`, migration 364) run active-active by several nodes over
/// one bucket and one database. Tenzir-shaped objects (a real Tenzir 6.19.1
/// `write_parquet` file, typed Parquet, NDJSON, gzipped NDJSON) are landed
/// under the source folder; every one must be claimed exactly once per
/// (key, etag), become exactly one set of bronze objects that bronze
/// admission admits under the folder's tenant/source/credential, and leave
/// the landing folder empty. A file abandoned by a dead node (expired lease)
/// is taken over by another node. Negatives: another tenant's folder is never
/// touched; an unknown source is refused whole and moved aside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn sovereign_tenzir_drop_is_claimed_once_across_active_active_converters() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
    let schema = format!("nan4629_{}", Uuid::new_v4().simple());
    let admin = ha_pool(&url, &schema).await;
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY);"))
        .execute(&admin)
        .await
        .expect("setup");
    sqlx::raw_sql(include_str!("../../migrations/postgres/364_landing_ocsf.sql")).execute(&admin).await.expect("364");
    sqlx::raw_sql(include_str!("../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&admin).await.expect("374");
    let landing = source();
    sqlx::query("INSERT INTO log_sources (id) VALUES ($1)").bind(landing.source_id).execute(&admin).await.unwrap();
    sqlx::query(
        "INSERT INTO landing_sources (source_id, route_key, credential_id, object_user, tenant_id) \
         VALUES ($1, $2, $3, 'nlhatenzir', $4)",
    )
    .bind(landing.source_id)
    .bind(&landing.route_key)
    .bind(landing.credential_id)
    .bind(HA_TENANT)
    .execute(&admin)
    .await
    .unwrap();

    // One bucket behind the datastore LB: every node sees the same objects.
    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let mut landed = Vec::new();
    let mut expect_rows = 0_u64;
    let tenzir = read_rows(TENZIR_AUTH_PARQUET, FileFormat::Parquet).unwrap().len() as u64;
    store.write(&ha_key(landing.source_id, "tenzir-auth.parquet"), TENZIR_AUTH_PARQUET.to_vec()).await.unwrap();
    landed.push(ha_key(landing.source_id, "tenzir-auth.parquet"));
    expect_rows += tenzir;
    for i in 0..12_i64 {
        let events: Vec<Value> = (0..3).map(|j| sysmon(Some(&format!("ha:{i}:{j}")), 1000 + i * 10 + j)).collect();
        let (name, body) = match i % 3 {
            0 => (format!("{}.parquet", Uuid::new_v4()), parquet(&events)),
            1 => (format!("{}.ndjson", Uuid::new_v4()), ndjson(&events)),
            _ => (format!("{}.ndjson.gz", Uuid::new_v4()), gzip(&ndjson(&events))),
        };
        let key = ha_key(landing.source_id, &name);
        store.write(&key, body).await.unwrap();
        landed.push(key);
        expect_rows += events.len() as u64;
    }
    // A node claimed this file and died: its lease is expired, not finished.
    let abandoned = ha_key(landing.source_id, &format!("{}.ndjson", Uuid::new_v4()));
    store.write(&abandoned, ndjson(&[sysmon(Some("ha:abandoned"), 7)])).await.unwrap();
    expect_rows += 1;
    {
        let dead = PgLedger::new(ha_pool(&url, &schema).await, std::time::Duration::from_secs(600), HA_TENANT);
        let entry = store.stat(&abandoned).await.unwrap();
        let candidate =
            Candidate { key: abandoned.clone(), etag: entry.etag().map(str::to_string), size: entry.content_length(), leased: None };
        let claimed = PrefixDiscover { ledger: &dead }.claim(&store, &candidate, Some(landing.source_id)).await.unwrap();
        assert!(matches!(claimed.claim, Claim::Owned { attempt: 1, .. }));
        sqlx::query("UPDATE landing_files SET lease_until = NOW() - INTERVAL '1 second' WHERE object_key = $1")
            .bind(&abandoned)
            .execute(&admin)
            .await
            .unwrap();
    }
    // Negatives: another tenant's folder, and a source nobody created.
    let foreign = format!("{LANDING_PREFIX}tenant_id=7b2d3f1a-0c8e-4d6f-a1b2-c3d4e5f60718/source={}/x.ndjson", landing.source_id);
    store.write(&foreign, ndjson(&[sysmon(Some("foreign"), 1)])).await.unwrap();
    let unknown = ha_key(Uuid::new_v4(), "x.ndjson");
    store.write(&unknown, ndjson(&[sysmon(Some("unknown"), 1)])).await.unwrap();

    let mut nodes = Vec::new();
    for _ in 0..HA_NODES {
        nodes.push(Converter {
            store: store.clone(),
            ledger: PgLedger::new(ha_pool(&url, &schema).await, std::time::Duration::from_secs(600), HA_TENANT),
            stage: stage(),
            tenant_id: HA_TENANT.into(),
            // Small ticks so the nodes interleave over the same listing.
            max_files_per_tick: 4,
            emit: BronzeObjects,
        });
    }
    let mut total = TickReport::default();
    for _ in 0..40 {
        let reports = futures::future::join_all(nodes.iter().map(Converter::tick)).await;
        for report in reports {
            let report = report.expect("tick");
            total.accepted += report.accepted;
            total.refused += report.refused;
            total.redelivered += report.redelivered;
            total.skipped += report.skipped;
            total.failed += report.failed;
        }
        if keys_under(&store, &format!("{LANDING_PREFIX}tenant_id={HA_TENANT}/")).await.is_empty() {
            break;
        }
    }
    assert!(
        keys_under(&store, &format!("{LANDING_PREFIX}tenant_id={HA_TENANT}/")).await.is_empty(),
        "every landed file finished: {total:?}"
    );
    assert_eq!(total.accepted, landed.len() + 1, "each file accepted by exactly one node: {total:?}");
    assert_eq!(total.refused, 1, "only the unknown source is refused: {total:?}");
    assert_eq!(keys_under(&store, REFUSED_PREFIX).await, vec![refused_key(&unknown)]);
    assert_eq!(keys_under(&store, &foreign).await, vec![foreign.clone()], "another tenant's folder is untouched");

    // The ledger: one row per (key, etag); one claim each, two for the takeover.
    let rows: Vec<(String, String, i32, i64)> =
        sqlx::query_as("SELECT object_key, state, attempts, rows_accepted FROM landing_files ORDER BY object_key")
            .fetch_all(&admin)
            .await
            .unwrap();
    assert_eq!(rows.len(), landed.len() + 2);
    for (key, state, attempts, _) in &rows {
        let expected = if *key == abandoned { 2 } else { 1 };
        assert_eq!(*attempts, expected, "{key}: claimed {attempts} times");
        assert_eq!(state, if *key == unknown { "refused" } else { "accepted" }, "{key}");
    }
    assert_eq!(rows.iter().map(|r| r.3 as u64).sum::<u64>(), expect_rows);

    // Exactly one bronze set, admitted under the folder's identity only.
    let bronze = keys_under(&store, BRONZE_PREFIX).await;
    assert_eq!(bronze.len(), landed.len() + 1, "no duplicate bronze from concurrent nodes");
    let dir = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    let mut events = Vec::new();
    for (index, key) in bronze.iter().enumerate() {
        assert!(key.contains(&format!("tenant_id={HA_TENANT}/")), "{key}");
        let bytes = store.read(key).await.unwrap().to_vec();
        events.extend(decode_bronze(&bytes).unwrap().into_iter().map(Result::unwrap));
        let path = dir.path().join(format!("{index}.parquet"));
        std::fs::write(&path, bytes).unwrap();
        paths.push(path);
    }
    let admission = crate::bronze::admit_bronze_files(&paths, HA_TENANT).unwrap();
    assert_eq!(admission.source_rows, expect_rows);
    assert_eq!(events.len() as u64, expect_rows);
    for event in &events {
        assert_eq!(event["metadata"]["tenant_uid"], HA_TENANT, "sender metadata cannot choose the tenant");
        assert_eq!(event["metadata"]["log_source"], landing.route_key.as_str());
        assert_eq!(event["metadata"]["nano_credential_id"], CREDENTIAL);
        assert_eq!(event["metadata"]["ingress_transport"], "landing_bucket");
    }
    let uids: std::collections::BTreeSet<_> =
        events.iter().filter_map(|e| e["metadata"]["uid"].as_str().map(str::to_string)).collect();
    assert!(uids.contains("ha:abandoned") && uids.contains("ha:11:2"));
    // One lister lease for the tenant, held by one of the nodes.
    let holders: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT tenant_id, holder FROM landing_listers").fetch_all(&admin).await.unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].0, HA_TENANT);
    assert!(nodes.iter().any(|node| node.ledger.node == holders[0].1));
    assert_eq!(nodes[0].ledger.backlog_age().await.unwrap(), None, "nothing left unfinished");

    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

/// NAN-4629 (coordinator Q-C, Q-D, Q-F) on the production `PgLedger`, two
/// tenants on one database (an MSSP sovereign install):
/// - another tenant's converter never sees or claims tenant A's rows, even
///   handed A's exact (key, etag);
/// - a source registered for tenant A is unknown in tenant B's folder, so
///   B's file naming it is refused whole (the folder must match the source's
///   credential tenant);
/// - one lister per tenant: a second node does not get the lease while it is
///   live and takes it over once it lapses; listing records `listed` rows
///   that any node claims (attempt 1), and drops a listed row whose object
///   vanished;
/// - the backlog age is the oldest unfinished landed file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn sovereign_ledger_is_tenant_bound_and_lists_under_one_lease() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
    const OTHER: &str = "7b2d3f1a-0c8e-4d6f-a1b2-c3d4e5f60718";
    let schema = format!("nan4629_{}", Uuid::new_v4().simple());
    let admin = ha_pool(&url, &schema).await;
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY);"))
        .execute(&admin)
        .await
        .expect("setup");
    sqlx::raw_sql(include_str!("../../migrations/postgres/364_landing_ocsf.sql")).execute(&admin).await.expect("364");
    sqlx::raw_sql(include_str!("../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&admin).await.expect("374");
    let landing = source();
    sqlx::query("INSERT INTO log_sources (id) VALUES ($1)").bind(landing.source_id).execute(&admin).await.unwrap();
    sqlx::query(
        "INSERT INTO landing_sources (source_id, route_key, credential_id, object_user, tenant_id) \
         VALUES ($1, $2, $3, 'nltenanta', $4)",
    )
    .bind(landing.source_id)
    .bind(&landing.route_key)
    .bind(landing.credential_id)
    .bind(HA_TENANT)
    .execute(&admin)
    .await
    .unwrap();
    // Legacy adoption never crosses tenants: B finds a source named for A.
    let lease = std::time::Duration::from_secs(600);
    let a1 = PgLedger::new(ha_pool(&url, &schema).await, lease, HA_TENANT);
    let a2 = PgLedger::new(ha_pool(&url, &schema).await, lease, HA_TENANT);
    let b = PgLedger::new(ha_pool(&url, &schema).await, lease, OTHER);
    assert_eq!(b.adopt_legacy_rows().await.unwrap(), (0, 0));

    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let a_key = ha_key(landing.source_id, "a.ndjson");
    store.write(&a_key, ndjson(&[sysmon(Some("tenant-a"), 1)])).await.unwrap();
    let gone = ha_key(landing.source_id, "gone.ndjson");
    store.write(&gone, ndjson(&[sysmon(Some("gone"), 2)])).await.unwrap();
    // B's folder, naming A's source: the folder decides the tenant.
    let b_key = format!("{LANDING_PREFIX}tenant_id={OTHER}/source={}/b.ndjson", landing.source_id);
    store.write(&b_key, ndjson(&[sysmon(Some("tenant-b"), 3)])).await.unwrap();

    // One lister per tenant; B's lease is its own.
    assert!(a1.hold_lister().await.unwrap());
    assert!(!a2.hold_lister().await.unwrap(), "a live lease is not shared");
    assert!(a1.hold_lister().await.unwrap(), "the holder renews");
    assert!(b.hold_lister().await.unwrap());
    // a2 claims what a1's listing recorded, without listing itself.
    let (open, found) = a1.pending(&store, HA_TENANT, 10).await.unwrap().unwrap();
    assert_eq!(open, 2);
    assert_eq!(found.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![a_key.as_str(), gone.as_str()]);
    assert!(a1.backlog_age().await.unwrap().is_some());
    let (_, seen_by_a2) = a2.pending(&store, HA_TENANT, 10).await.unwrap().unwrap();
    assert_eq!(seen_by_a2, found);
    // Tenant B sees none of A's rows, and cannot claim them even by name.
    let (b_open, b_found) = b.pending(&store, OTHER, 10).await.unwrap().unwrap();
    assert_eq!((b_open, b_found.iter().map(|c| c.key.clone()).collect::<Vec<_>>()), (1, vec![b_key.clone()]));
    let a_etag = found[0].etag.clone().unwrap();
    assert_eq!(b.claim(&a_key, &a_etag, 1, Some(landing.source_id)).await.unwrap(), Claim::Leased);
    assert!(b.pending(&store, HA_TENANT, 10).await.is_err(), "a ledger refuses another tenant's folder");
    let state: (String, i32) = sqlx::query_as("SELECT state, attempts FROM landing_files WHERE object_key = $1")
        .bind(&a_key)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(state, ("listed".to_string(), 0), "B's claim attempt left A's row untouched");
    // A's source is unknown to B's ledger: B's file naming it is refused.
    assert!(b.source(landing.source_id).await.unwrap().is_none());
    assert!(a2.source(landing.source_id).await.unwrap().unwrap().active);
    let b_converter = Converter {
        store: store.clone(),
        ledger: b,
        stage: stage(),
        tenant_id: OTHER.into(),
        max_files_per_tick: 10,
        emit: BronzeObjects,
    };
    let report = b_converter.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused), (0, 1));
    assert_eq!(keys_under(&store, REFUSED_PREFIX).await, vec![refused_key(&b_key)]);
    let reason: String = sqlx::query_scalar("SELECT reason FROM landing_files WHERE object_key = $1")
        .bind(&b_key)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(reason, "source_unknown");

    // A listed object that vanished is dropped from the queue by the next
    // complete listing (after the listing clock passed its first sighting).
    store.delete(&gone).await.unwrap();
    sqlx::query("UPDATE landing_files SET first_seen_at = NOW() - INTERVAL '1 minute' WHERE object_key = $1")
        .bind(&gone)
        .execute(&admin)
        .await
        .unwrap();
    assert_eq!(a1.list_into_ledger(&store).await.unwrap(), 1);
    let left: Vec<String> = sqlx::query_scalar("SELECT object_key FROM landing_files WHERE tenant_id = $1 ORDER BY object_key")
        .bind(HA_TENANT)
        .fetch_all(&admin)
        .await
        .unwrap();
    assert_eq!(left, vec![a_key.clone()]);

    // Lister failover: a1 stops renewing; a2 takes the lease once it lapses.
    sqlx::query("UPDATE landing_listers SET lease_until = NOW() - INTERVAL '1 second' WHERE tenant_id = $1")
        .bind(HA_TENANT)
        .execute(&admin)
        .await
        .unwrap();
    assert!(a2.hold_lister().await.unwrap(), "a lapsed lease fails over");
    assert!(!a1.hold_lister().await.unwrap(), "the old holder does not take it back while it is live");

    // a2 converts A's file from the ledger (attempt 1); the backlog drains.
    let a_converter = Converter {
        store: store.clone(),
        ledger: a2,
        stage: stage(),
        tenant_id: HA_TENANT.into(),
        max_files_per_tick: 10,
        emit: BronzeObjects,
    };
    let report = a_converter.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused, report.backlog_age_secs), (1, 0, None));
    let row: (String, i32) = sqlx::query_as("SELECT state, attempts FROM landing_files WHERE object_key = $1")
        .bind(&a_key)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(row, ("accepted".to_string(), 1));
    // B's row is still B's: A's ledger never touched it.
    let b_tenant: Option<String> = sqlx::query_scalar("SELECT tenant_id FROM landing_files WHERE object_key = $1")
        .bind(&b_key)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(b_tenant.as_deref(), Some(OTHER));

    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

/// NAN-4629 (coordinator Q-A): the converter's policy reaches only its
/// tenant's landing folder, list/get/delete only (no put anywhere).
#[test]
fn converter_policy_is_scoped_to_the_tenant_landing_folder() {
    let policy = converter_policy("nano-lake", HA_TENANT);
    let statements = policy["Statement"].as_array().unwrap();
    assert_eq!(statements.len(), 2);
    let folder = format!("landing-ocsf-v1/tenant_id={HA_TENANT}/");
    assert_eq!(statements[0]["Action"], json!(["s3:ListBucket"]));
    assert_eq!(statements[0]["Resource"], json!(["arn:aws:s3:::nano-lake"]));
    assert_eq!(statements[0]["Condition"]["StringLike"]["s3:prefix"], json!([folder.clone(), format!("{folder}*")]));
    assert_eq!(statements[1]["Action"], json!(["s3:GetObject", "s3:DeleteObject"]));
    assert_eq!(statements[1]["Resource"], json!([format!("arn:aws:s3:::nano-lake/{folder}*")]));
    // Negative: no put, no bronze or refused folder, no bucket-wide object
    // action, no other verbs.
    let text = policy.to_string();
    assert!(!text.contains("bronze") && !text.contains("nano-lake/*") && !text.contains("s3:*"));
    assert!(!text.contains("PutObject") && !text.contains("refused"));
    for statement in statements {
        for resource in statement["Resource"].as_array().unwrap() {
            let resource = resource.as_str().unwrap();
            assert!(resource == "arn:aws:s3:::nano-lake" || resource.contains(&format!("tenant_id={HA_TENANT}/")), "{resource}");
        }
    }
}

/// NAN-4629 (coordinator Q-B): sovereign bronze is published through the
/// consumer store's immutable create, never written raw to the landing store.
#[tokio::test]
async fn sovereign_bronze_is_published_through_put_if_absent() {
    use crate::parts::part_log::ObjectStore;
    #[derive(Default)]
    struct Published(Mutex<Vec<(String, Vec<u8>)>>);
    #[async_trait]
    impl ObjectStore for Published {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, b)| b.clone()))
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            let mut objects = self.0.lock().unwrap();
            if objects.iter().any(|(k, _)| k == key) {
                return Ok(false);
            }
            objects.push((key.to_string(), bytes.to_vec()));
            Ok(true)
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self.0.lock().unwrap().iter().filter(|(k, _)| k.starts_with(prefix)).map(|(k, _)| k.clone()).collect())
        }
        async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
            anyhow::bail!("published bronze is immutable")
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            anyhow::bail!("published bronze is immutable")
        }
    }
    let landing = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let converter = Converter {
        store: landing.clone(),
        ledger: MemoryLedger { sources: vec![source()], ..Default::default() },
        stage: stage(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 10,
        emit: PublishedBronze { store: Published::default() },
    };
    landing.write(&key("x.parquet"), TENZIR_AUTH_PARQUET.to_vec()).await.unwrap();
    let unknown = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={}/y.ndjson", Uuid::new_v4());
    landing.write(&unknown, ndjson(&[sysmon(Some("u"), 1)])).await.unwrap();
    let report = converter.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused), (1, 1), "{report:?}");
    assert!(keys_under(&landing, BRONZE_PREFIX).await.is_empty(), "nothing raw next to the landing folder");
    assert!(keys_under(&landing, REFUSED_PREFIX).await.is_empty(), "the refused copy is published, not written raw");
    assert!(keys_under(&landing, LANDING_PREFIX).await.is_empty());
    let mut published = converter.emit.store.0.lock().unwrap().clone();
    let refused_at = published.iter().position(|(k, _)| *k == refused_key(&unknown)).expect("refused copy published");
    assert_eq!(published.remove(refused_at).1, ndjson(&[sysmon(Some("u"), 1)]));
    assert!(!published.is_empty());
    for (key, bytes) in published.iter() {
        assert!(key.starts_with(BRONZE_PREFIX) && key.contains(&format!("tenant_id={TENANT}/")), "{key}");
        assert!(decode_bronze(bytes).unwrap().into_iter().all(|row| row.is_ok()));
    }
}

/// NAN-4629 (coordinator Q-B): the published refused copy is write-if-absent
/// yet never lossy. A retry of the same refusal is a no-op; a second, different
/// refused file under the same landed key is kept beside the first.
#[tokio::test]
async fn published_refused_copy_never_drops_a_second_file_under_the_same_key() {
    use crate::parts::part_log::ObjectStore;
    #[derive(Default)]
    struct Published(Mutex<Vec<(String, Vec<u8>)>>);
    #[async_trait]
    impl ObjectStore for Published {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, b)| b.clone()))
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            let mut objects = self.0.lock().unwrap();
            if objects.iter().any(|(k, _)| k == key) {
                return Ok(false);
            }
            objects.push((key.to_string(), bytes.to_vec()));
            Ok(true)
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self.0.lock().unwrap().iter().filter(|(k, _)| k.starts_with(prefix)).map(|(k, _)| k.clone()).collect())
        }
        async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
            anyhow::bail!("immutable")
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            anyhow::bail!("immutable")
        }
    }
    let landing = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let emit = PublishedBronze { store: Published::default() };
    let landed = key("same.ndjson");
    landing.write(&landed, b"first".to_vec()).await.unwrap();
    assert_eq!(emit.keep_refused(&landing, &landed).await.unwrap(), RefusedCopy::Kept);
    assert_eq!(emit.keep_refused(&landing, &landed).await.unwrap(), RefusedCopy::Kept, "a retried refusal is idempotent");
    assert_eq!(emit.store.0.lock().unwrap().len(), 1);
    landing.write(&landed, b"second".to_vec()).await.unwrap();
    assert_eq!(emit.keep_refused(&landing, &landed).await.unwrap(), RefusedCopy::Kept);
    let kept = emit.store.0.lock().unwrap().clone();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0], (refused_key(&landed), b"first".to_vec()));
    assert_eq!(
        kept[1],
        (format!("{}.sha256-{}", refused_key(&landed), hex::encode(Sha256::digest(b"second"))), b"second".to_vec())
    );
    // Gone already (a crash after the delete): nothing to keep.
    landing.delete(&landed).await.unwrap();
    assert_eq!(emit.keep_refused(&landing, &landed).await.unwrap(), RefusedCopy::Kept);
}

/// NAN-4629 (coordinator Q-C): pre-374 rows on a database that turns out to
/// hold two tenants. Whichever converter adopts first, it takes only its own
/// files (by folder) and only sources whose files are in its folder; a
/// file-less source is adopted only when the database shows no other tenant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn legacy_adoption_never_takes_another_tenants_source() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
    const OTHER: &str = "7b2d3f1a-0c8e-4d6f-a1b2-c3d4e5f60718";
    let schema = format!("nan4629_{}", Uuid::new_v4().simple());
    let admin = ha_pool(&url, &schema).await;
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY);"))
        .execute(&admin)
        .await
        .expect("setup");
    sqlx::raw_sql(include_str!("../../migrations/postgres/364_landing_ocsf.sql")).execute(&admin).await.expect("364");
    // Pre-374 state: A's source with a file in A's folder, a file-less source.
    let with_files = source();
    let file_less = LandingSource { source_id: Uuid::new_v4(), credential_id: Uuid::new_v4(), ..source() };
    for (s, user) in [(&with_files, "nllegacya"), (&file_less, "nllegacyz")] {
        sqlx::query("INSERT INTO log_sources (id) VALUES ($1)").bind(s.source_id).execute(&admin).await.unwrap();
        sqlx::query("INSERT INTO landing_sources (source_id, route_key, credential_id, object_user) VALUES ($1, $2, $3, $4)")
            .bind(s.source_id)
            .bind(&s.route_key)
            .bind(s.credential_id)
            .bind(user)
            .execute(&admin)
            .await
            .unwrap();
    }
    let a_key = ha_key(with_files.source_id, "legacy.ndjson");
    sqlx::query(
        "INSERT INTO landing_files (object_key, etag, source_id, size_bytes, state, attempts, finished_at) \
         VALUES ($1, 'e1', $2, 1, 'accepted', 1, NOW())",
    )
    .bind(&a_key)
    .bind(with_files.source_id)
    .execute(&admin)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!("../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&admin).await.expect("374");
    let lease = std::time::Duration::from_secs(600);
    let a = PgLedger::new(ha_pool(&url, &schema).await, lease, HA_TENANT);
    let b = PgLedger::new(ha_pool(&url, &schema).await, lease, OTHER);
    // B first: A's file is outside B's folder, so B adopts nothing.
    assert_eq!(b.adopt_legacy_rows().await.unwrap(), (0, 0));
    assert!(b.source(with_files.source_id).await.unwrap().is_none());
    assert!(b.source(file_less.source_id).await.unwrap().is_none());
    // A: its file, the source whose file is in A's folder, and the file-less
    // source (no other tenant's source or file exists yet).
    assert_eq!(a.adopt_legacy_rows().await.unwrap(), (1, 2));
    assert!(a.source(with_files.source_id).await.unwrap().unwrap().active);
    assert!(a.source(file_less.source_id).await.unwrap().unwrap().active);
    let tenants: Vec<Option<String>> = sqlx::query_scalar("SELECT tenant_id FROM landing_sources ORDER BY source_id")
        .fetch_all(&admin)
        .await
        .unwrap();
    assert_eq!(tenants, vec![Some(HA_TENANT.to_string()); 2]);
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

/// An in-memory consumer store (write-if-absent, immutable).
#[derive(Default)]
struct PublishedMem(Mutex<Vec<(String, Vec<u8>)>>);
#[async_trait]
impl crate::parts::part_log::ObjectStore for PublishedMem {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, b)| b.clone()))
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let mut objects = self.0.lock().unwrap();
        if objects.iter().any(|(k, _)| k == key) {
            return Ok(false);
        }
        objects.push((key.to_string(), bytes.to_vec()));
        Ok(true)
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().iter().filter(|(k, _)| k.starts_with(prefix)).map(|(k, _)| k.clone()).collect())
    }
    async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
        anyhow::bail!("immutable")
    }
    async fn delete(&self, _key: &str) -> Result<()> {
        anyhow::bail!("immutable")
    }
}

/// NAN-4629 (coordinator, data loss rule): a refused file the consumer store
/// cannot take (over its 64 MiB write bound, or empty) is never deleted
/// without a copy. It stays where it landed, is recorded refused in place,
/// and later ticks neither reclaim nor delete it as a redelivery.
#[tokio::test]
async fn a_refused_file_too_big_to_publish_stays_where_it_landed() {
    let landing = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let converter = Converter {
        store: landing.clone(),
        ledger: MemoryLedger { sources: vec![source()], ..Default::default() },
        stage: stage(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 10,
        emit: PublishedBronze { store: PublishedMem::default() },
    };
    // Unknown source: refused whole before any read or conversion.
    let folder = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={}/", Uuid::new_v4());
    let big = format!("{folder}big.ndjson");
    let empty = format!("{folder}empty.ndjson");
    let small = format!("{folder}small.ndjson");
    let big_len = usize::try_from(MAX_PUBLISHED_REFUSED_BYTES).unwrap() + 1;
    landing.write(&big, vec![b'x'; big_len]).await.unwrap();
    landing.write(&empty, Vec::<u8>::new()).await.unwrap();
    landing.write(&small, ndjson(&[sysmon(Some("s"), 1)])).await.unwrap();
    for round in 0..3 {
        let report = converter.tick().await.unwrap();
        if round == 0 {
            assert_eq!((report.accepted, report.refused), (0, 3), "{report:?}");
        } else {
            assert_eq!((report.refused, report.redelivered, report.skipped), (0, 0, 2), "round {round}: {report:?}");
        }
        // Never deleted without a copy: the two uncopyable files stay, byte for byte.
        assert_eq!(landing.read(&big).await.unwrap().len(), big_len);
        assert!(landing.exists(&empty).await.unwrap());
        // The copyable one was published, then deleted.
        assert!(!landing.exists(&small).await.unwrap());
    }
    let published = converter.emit.store.0.lock().unwrap().clone();
    assert_eq!(published.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(), vec![refused_key(&small)]);
    let files = converter.ledger.files.lock().unwrap().clone();
    let state_of = |key: &str| files.iter().find(|f| f.0 == key).map(|f| (f.2.clone(), f.3.clone())).unwrap();
    assert_eq!(state_of(&big), ("refused_in_place".to_string(), Some("source_unknown".to_string())));
    assert_eq!(state_of(&empty).0, "refused_in_place");
    assert_eq!(state_of(&small).0, "refused");
}

/// A ledger that cannot record a refusal in place refuses: the file is not
/// deleted (the default `Ledger::refused_in_place`).
#[tokio::test]
async fn a_ledger_without_in_place_support_never_deletes_the_file() {
    struct NoInPlace(MemoryLedger);
    #[async_trait]
    impl Ledger for NoInPlace {
        async fn source(&self, id: Uuid) -> Result<Option<LandingSource>> { self.0.source(id).await }
        async fn claim(&self, k: &str, e: &str, s: u64, id: Option<Uuid>) -> Result<Claim> { self.0.claim(k, e, s, id).await }
        async fn accepted(&self, id: i64, c: &Converted, b: &str) -> Result<()> { self.0.accepted(id, c, b).await }
        async fn refused(&self, id: i64, r: &str, n: u64, s: Option<&str>) -> Result<()> { self.0.refused(id, r, n, s).await }
        async fn redelivered(&self, id: i64) -> Result<()> { self.0.redelivered(id).await }
    }
    let landing = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let converter = Converter {
        store: landing.clone(),
        ledger: NoInPlace(MemoryLedger { sources: vec![source()], ..Default::default() }),
        stage: stage(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 10,
        emit: PublishedBronze { store: PublishedMem::default() },
    };
    let empty = format!("{LANDING_PREFIX}tenant_id={TENANT}/source={}/empty.ndjson", Uuid::new_v4());
    landing.write(&empty, Vec::<u8>::new()).await.unwrap();
    let report = converter.tick().await.unwrap();
    assert_eq!((report.refused, report.failed), (0, 1), "{report:?}");
    assert!(landing.exists(&empty).await.unwrap());
}

/// NAN-4629 on PostgreSQL: a refused-in-place row stays refused, is never
/// claimed, redelivered or pruned, and its file is never deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn pg_ledger_keeps_a_refused_in_place_file_and_never_deletes_it() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
    let schema = format!("nan4629_{}", Uuid::new_v4().simple());
    let admin = ha_pool(&url, &schema).await;
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY);"))
        .execute(&admin)
        .await
        .expect("setup");
    sqlx::raw_sql(include_str!("../../migrations/postgres/364_landing_ocsf.sql")).execute(&admin).await.expect("364");
    sqlx::raw_sql(include_str!("../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&admin).await.expect("374");
    let landing = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let converter = Converter {
        store: landing.clone(),
        ledger: PgLedger::new(ha_pool(&url, &schema).await, std::time::Duration::from_secs(600), HA_TENANT),
        stage: stage(),
        tenant_id: HA_TENANT.into(),
        max_files_per_tick: 10,
        emit: PublishedBronze { store: PublishedMem::default() },
    };
    // No source registered: refused source_unknown; empty, so no copy.
    let empty = ha_key(Uuid::new_v4(), "empty.ndjson");
    landing.write(&empty, Vec::<u8>::new()).await.unwrap();
    let report = converter.tick().await.unwrap();
    assert_eq!(report.refused, 1, "{report:?}");
    let row: (String, bool, Option<String>) =
        sqlx::query_as("SELECT state, refused_in_place, reason FROM landing_files WHERE object_key = $1")
            .bind(&empty)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(row, ("refused".to_string(), true, Some("source_unknown".to_string())));
    assert!(landing.exists(&empty).await.unwrap());
    // Later ticks: not pending, not reclaimed, not deleted as a redelivery.
    let report = converter.tick().await.unwrap();
    assert_eq!((report.refused, report.redelivered, report.accepted), (0, 0, 0), "{report:?}");
    let etag = landing.stat(&empty).await.unwrap().etag().map(str::to_string);
    let (etag, _, _) = landed_etag(&landing, &empty, etag.as_deref(), 0).await.unwrap();
    assert_eq!(converter.ledger.claim(&empty, &etag, 0, None).await.unwrap(), Claim::Leased);
    assert!(landing.exists(&empty).await.unwrap());
    // Not pruned while it exists, however old.
    sqlx::query("UPDATE landing_files SET finished_at = NOW() - INTERVAL '400 days' WHERE object_key = $1")
        .bind(&empty)
        .execute(&admin)
        .await
        .unwrap();
    assert_eq!(converter.ledger.prune().await.unwrap(), 0);
    assert_eq!(converter.ledger.backlog_age().await.unwrap(), None);
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

/// NAN-4675: a Vector-less tenant's platform audit, delivered by the hosted control plane
/// into its bucket drop under the platform `audit` landing source, converts
/// with the PRODUCTION stage (`LandingOcsfStage::new(1)`, as `landing_cell`
/// builds it) into bronze that the real admission admits as
/// `log_source = audit`, including the NAN-3304 null-only rows; a foreign
/// tenant's row in the same file is counted refused, never landed.
#[test]
fn cell_feature_lean_landing_platform_audit_v1_is_backed() {
    use nanosiem_core::audit::{AuditEvent, AuditSource};
    use nanosiem_core::parsers::landing_ocsf::PLATFORM_AUDIT_ROUTE_KEY;
    assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_landing_platform_audit_v1"));
    const T: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";
    let at = chrono::DateTime::parse_from_rfc3339("2026-10-21T06:02:00.123Z").unwrap().with_timezone(&Utc);
    let event = |id: &str, tenant: &str, client: bool| {
        let mut builder = AuditEvent::builder(AuditSource::Detection, "rule_created").success(true);
        if client {
            builder = builder.actor(Some(Uuid::nil()), Some("dan@nano.rs".to_string()));
        }
        let mut v = builder.build().to_ocsf_event_for_lake(at, Uuid::parse_str(id).unwrap(), tenant);
        if client {
            v["src_endpoint"]["ip"] = json!("10.1.2.3");
        }
        v
    };
    let ids = ["018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e01", "018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e02", "018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e03"];
    // Exactly the body the control plane reserves: one OCSF mirror per line.
    let file = ndjson(&[event(ids[0], T, true), event(ids[1], T, false), event(ids[2], OTHER, true)]);
    let audit = LandingSource { route_key: PLATFORM_AUDIT_ROUTE_KEY.into(), ..source() };
    let stage = LandingOcsfStage::new(1).unwrap();
    let converted = convert_file(&file, FileFormat::Ndjson { gzip: false }, &stage, T, &audit, Utc::now()).unwrap();
    assert_eq!((converted.rows_accepted, converted.rows_refused), (2, 1), "the foreign tenant's row is refused");
    assert_eq!(converted.objects.len(), 1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.parquet");
    std::fs::write(&path, &converted.objects[0].1).unwrap();
    let admitted = crate::bronze::admit_bronze_files(&[path], T).unwrap();
    assert_eq!(admitted.source_rows, 2);
    assert_eq!(admitted.batch.len(), 2, "both rows pass strict OCSF 1.9 admission, the null-only one included");
    let mut uids: Vec<String> = admitted.batch.rows().iter().map(|row| {
        let e = &row.ocsf_event;
        assert_eq!(e["metadata"]["log_source"], "audit");
        assert_eq!(e["metadata"]["tenant_uid"], T);
        assert_eq!(e["metadata"]["ingress_transport"], "landing_bucket");
        assert_eq!(e["class_uid"], 6003);
        e["metadata"]["uid"].as_str().unwrap().to_string()
    }).collect();
    uids.sort();
    assert_eq!(uids, [ids[0], ids[1]], "the audit event ids stay the uids (replays dedupe in ingest[T])");
}


#[path = "landing_throughput_tests.rs"]
mod throughput;
