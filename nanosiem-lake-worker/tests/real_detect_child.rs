// SPDX-License-Identifier: AGPL-3.0-or-later

//! A real Role::Detect process, owner-signed source part and authenticated
//! fd3 control/RPC transport. Run with a disposable PG18 admin URL in
//! NANO_RISK_TEST_PG; the test reexecs in a user namespace for the jail.

use bytes::Bytes;
use arrow_json::reader::{infer_json_schema_from_seekable, ReaderBuilder};
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use nanosiem_lake_cell::contract::{ToChild, ToSupervisor, PROTOCOL_VERSION};
use nanosiem_lake_cell::fdpass;
use nanosiem_lake_worker::part_ingest::cell::HttpPartSigner;
use nanosiem_lake_worker::part_ingest::schema::{decode, infer_schema};
use nanosiem_lake_worker::part_ingest::writer::{
    publish_parts, PartDraft, PartWriter, PartialSource,
};
use nanosiem_lake_worker::parts::format::schema_fingerprint;
use nanosiem_lake_worker::parts::levels::Level;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, LogOp, PartLogWriter, SourceRef};
use nanosiem_lake_worker::parts::provenance::{
    Admission, PartInputs, PartSigner, SourceObject, TenantKeySet,
};
use nanosiem_lake_worker::parts::{event_hour_of, DedupWindow};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Cursor};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const TENANT: &str = "00000000-0000-4000-8000-000000000001";
pub(crate) const FOREIGN: &str = "00000000-0000-4000-8000-000000000002";

/// Only async-signal-safe syscalls may run in a multi-threaded parent's
/// pre_exec closure. Build the C path before fork, then attach before exec.
pub(crate) fn attach_self_to_cgroup(target: &std::ffi::CStr) -> std::io::Result<()> {
    let fd = unsafe { libc::open(target.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let mut digits = [0_u8; 20];
    let mut pid = unsafe { libc::getpid() } as u64;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 { break; }
    }
    let count = unsafe { libc::write(fd, digits[start..].as_ptr().cast(), digits.len() - start) };
    let error = if count < 0 { Some(std::io::Error::last_os_error()) } else { None };
    unsafe { libc::close(fd); }
    if let Some(error) = error { return Err(error); }
    if count as usize != digits.len() - start {
        return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short cgroup.procs write"));
    }
    Ok(())
}
const TOKEN: &[u8] = b"fixture-bootstrap-token";
fn detect_binary() -> PathBuf {
    std::env::var_os("NANO_RISK_TEST_DETECT_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_lake_part_query").map(PathBuf::from))
        .expect("built lake_part_query binary required")
}

pub(crate) struct Process(pub(crate) Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn release_fixture_library_cache(path: &Path) {
    // The fixture copied and hashed this inode in the test-driver cgroup.
    // Evict those clean pages before the native child faults them so the
    // delegated query role pays for its own library in memory.current.
    let file = std::fs::File::open(path).unwrap();
    file.sync_all().unwrap();
    assert_eq!(unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) }, 0);
}

fn checked(cmd: &mut Command) {
    let result = cmd.output().expect("run fixture command");
    assert!(
        result.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn pg_port(url: &str) -> u16 {
    let authority = url.split('/').nth(2).expect("PG authority");
    authority
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .expect("PG port")
}

async fn setup_pg(admin_url: &str) {
    assert!(
        admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "NANO_RISK_TEST_PG must name a disposable loopback risktest database"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url)
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        (180_000..190_000).contains(&version),
        "fixture requires PostgreSQL 18"
    );
    for sql in [
        "DROP SCHEMA IF EXISTS nano_shared CASCADE",
        "DROP TABLE IF EXISTS detection_finding_lake_outbox",
        "DROP ROLE IF EXISTS risk_drain",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    for sql in [
        "CREATE SCHEMA nano_shared",
        "CREATE ROLE risk_drain LOGIN",
        "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, PRIMARY KEY (tenant_id, finding_id))",
        "CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT '00000000-0000-4000-8000-000000000001'::uuid $$",
        "CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user = 'risk_drain' THEN 'finding_drain' END $$",
        "GRANT USAGE ON SCHEMA nano_shared TO risk_drain",
        "GRANT EXECUTE ON FUNCTION nano_shared.lake_data_path_tenant_id() TO risk_drain",
        "GRANT EXECUTE ON FUNCTION nano_shared.lake_data_path_capability() TO risk_drain",
        "GRANT SELECT, UPDATE ON detection_finding_lake_outbox TO risk_drain",
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_select ON detection_finding_lake_outbox FOR SELECT USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())",
        "CREATE POLICY tenant_update ON detection_finding_lake_outbox FOR UPDATE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    pool.close().await;
}

pub(crate) async fn signed_source(
    store_dir: &Path,
    work: &Path,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
) -> i64 {
    signed_source_for(TENANT, store_dir, work, signer, trusted).await
}

pub(crate) async fn signed_source_for(
    tenant: &str,
    store_dir: &Path,
    work: &Path,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
) -> i64 {
    let time_us = chrono::Utc::now().timestamp_micros() - 30_000_000;
    let time = chrono::DateTime::from_timestamp_micros(time_us)
        .unwrap()
        .to_rfc3339();
    let event = json!({
        "time": time, "message": "detect-real-source-row", "class_uid": 3002,
        "metadata": {"uid": "source-1", "tenant_uid": tenant, "log_source": "apache"},
        "src_endpoint": {"ip": "10.23.45.67"},
        "device": {"hostname": "risk-fixture-host"}
    });
    let schema = std::sync::Arc::new(infer_schema(&[&event]).unwrap());
    let batch = decode(schema.clone(), &[&event]).unwrap();
    let draft = PartDraft {
        tenant_id: tenant.into(),
        signer_key_id: "fixture-owner".into(),
        level: Level::L0,
        event_hour: event_hour_of(time_us),
        schema_fingerprint: schema_fingerprint(&schema).unwrap(),
        schema,
        inputs: PartInputs::Sources {
            sources: vec![SourceObject {
                key: "fixture/source.parquet".into(),
                version: "1".into(),
                bytes: 1,
                sha256: "a".repeat(64),
                rows: 1,
                edge_sha256: None,
            }],
            edge_log: None,
        },
        admission: Some(Admission {
            ocsf_version: "1.9.0".into(),
            admission_contract: "fixture-v1".into(),
            feed_pins: Default::default(),
        }),
        rows_in: 1,
        duplicates_dropped: 0,
        window: DedupWindow::Exact,
        build: "risk9c-fixture".into(),
    };
    let mut writer =
        PartWriter::create(work, draft, PartialSource::FromRows, time_us / 1000, 1).unwrap();
    writer.write(&batch).unwrap();
    let finished = writer.finish().unwrap();
    let store = LocalObjectStore::new(store_dir).unwrap();
    let refs = publish_parts(&store, signer, trusted, &[finished])
        .await
        .unwrap();
    assert_eq!(refs.len(), 1);
    let mut log = PartLogWriter::open(&store, tenant, 7, &batch.schema(), time_us / 1000)
        .await
        .unwrap();
    log.append(
        LogOp::Add {
            parts: refs,
            consumed: vec![SourceRef {
                key: "fixture/source.parquet".into(),
                version: "1".into(),
                sha256: "a".repeat(64),
            }],
            edge_log: None,
        },
        time_us / 1000 + 1,
    )
    .await
    .unwrap();
    time_us
}

/// Simulate the external Vector handoff only. The production ingest child
/// performs admission, enrichment, dedup, owner signing and part publication.
pub(crate) fn enqueue_bronze_source(
    tenant: &str,
    dir: &Path,
    sequence: u64,
    rows: usize,
    period_secs: usize,
    end_lag_secs: i64,
    matching_uid: Option<&str>,
) -> (i64, PathBuf) {
    enqueue_bronze_source_with_match(tenant, dir, sequence, rows, period_secs,
        end_lag_secs, matching_uid, true)
}

/// Emit an ordinary bronze notice at the producer's actual wall-clock tick.
/// Background ticks carry no matching row; the matching tick uses the same
/// production admission path as every other tick.
pub(crate) fn enqueue_bronze_source_with_match(
    tenant: &str,
    dir: &Path,
    sequence: u64,
    rows: usize,
    period_secs: usize,
    end_lag_secs: i64,
    matching_uid: Option<&str>,
    matching_first: bool,
) -> (i64, PathBuf) {
    use sha2::Digest;
    let mut time_us = chrono::Utc::now().timestamp_micros() - end_lag_secs * 1_000_000;
    // A one-second paced object can straddle an event-hour boundary even
    // though its notice arrived on time. Keep that object in the preceding
    // hour (at most two seconds of event-time adjustment) so production's
    // single-hour part invariant is exercised without dropping a wall tick.
    if period_secs == 1 {
        while event_hour_of(time_us - 1_000_000) != event_hour_of(time_us) {
            time_us -= 1_000_000;
        }
    }
    assert_eq!(event_hour_of(time_us - period_secs as i64 * 1_000_000), event_hour_of(time_us),
        "bronze source crosses an event-hour boundary; split the fixture object");
    let mut jsonl = Vec::new();
    for index in 0..rows {
        let uid = if index == 0 { matching_uid.map(str::to_owned)
            .unwrap_or_else(|| format!("load-{sequence:08}-{index:08}")) }
            else { format!("load-{sequence:08}-{index:08}") };
        let raw = format!("raw {uid}");
        let event = json!({
            "activity_id":1, "activity_name":"Logon", "category_name":"Identity & Access Management",
            "category_uid":3, "class_name":"Authentication", "class_uid":3002,
            "type_uid":300201, "severity":"Informational", "severity_id":1,
            "status":"Failure", "status_id":2,
            "actor":{"user":{"name":"fixture-user"}},
            "message": if index == 0 && matching_first { "detect-real-source-row" } else { "load-background-row" },
            "raw_data":raw, "raw_data_size":raw.len(),
            "time":chrono::DateTime::from_timestamp_micros(
                time_us - ((rows - 1 - index) * period_secs * 1_000_000 / rows) as i64
            ).unwrap().to_rfc3339(),
            "metadata":{"uid":uid,"tenant_uid":tenant,"log_source":"apache","log_name":"security","version":"1.9.0",
                "product":{"name":"fixture","vendor_name":"nano"}},
            "src_endpoint":{"ip":"10.23.45.67","hostname":"risk-fixture-host"},
            "dst_endpoint":{"ip":"192.168.1.20"},
            "user":{"name":"fixture-user","uid":"S-1-5-21-1"}
        });
        serde_json::to_writer(&mut jsonl, &event).unwrap();
        jsonl.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(jsonl.clone()), None).unwrap();
    let reader = ReaderBuilder::new(std::sync::Arc::new(schema)).build(Cursor::new(jsonl)).unwrap();
    let key = format!("bronze-v2/shard=0/tenant_id={tenant}/load-{sequence:08}.parquet");
    let path = dir.join("store").join(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), batch.schema(), None).unwrap())
            .write(&batch).unwrap();
    }
    writer.expect("nonempty bronze object").close().unwrap();
    let data = std::fs::read(&path).unwrap();
    let notice = json!({"id":format!("load-{sequence:08}"),"notice":{
        "tenant_id":tenant,"key":key,"version":"1","bytes":data.len(),
        "sha256":hex::encode(sha2::Sha256::digest(&data)),"edge_sha256":null,
        "notified_at_ms":chrono::Utc::now().timestamp_millis()}});
    let notice_dir = dir.join("notices");
    std::fs::create_dir_all(&notice_dir).unwrap();
    let final_path = notice_dir.join(format!("load-{sequence:08}.json"));
    let temp_path = notice_dir.join(format!("load-{sequence:08}.tmp"));
    std::fs::write(&temp_path, serde_json::to_vec(&notice).unwrap()).unwrap();
    std::fs::rename(temp_path, &final_path).unwrap();
    (time_us, final_path)
}

#[test]
fn measured_bronze_source_is_accepted_by_production_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (_source_us, _notice) = enqueue_bronze_source(TENANT, dir.path(), 0, 1, 1, 3, None);
    let path = dir.path().join("store").join(format!(
        "bronze-v2/shard=0/tenant_id={TENANT}/load-00000000.parquet"));
    nanosiem_lake_worker::bronze::admit_bronze_files(&[path], TENANT)
        .expect("measured external source must survive the real bronze admission contract");
}

pub(crate) fn https_stub(dir: &Path, body: &Value, store: &Path) -> (Process, u16, PathBuf) {
    https_stub_for(TENANT, dir, body, store)
}

pub(crate) fn https_stub_for(tenant: &str, dir: &Path, body: &Value, store: &Path) -> (Process, u16, PathBuf) {
    let body_path = dir.join(format!("exchange-{}.json", body["writer_epoch"]));
    std::fs::write(&body_path, serde_json::to_vec(body).unwrap()).unwrap();
    std::fs::set_permissions(&body_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cert = dir.join("leaf.pem");
    let key = dir.join("leaf.key");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().join("nanosiem-lake-worker/tests/support/detect_fixture_https.py");
    let mut command = Command::new("python3");
    command
        .arg(script)
        .args([
            body_path.as_os_str(),
            store.as_os_str(),
            cert.as_os_str(),
            key.as_os_str(),
        ])
        .arg(tenant)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(root) = std::env::var_os("NANO_RISK_ROLE_CGROUP_ROOT") {
        let target = PathBuf::from(root).join(tenant).join("owner/cgroup.procs");
        let target = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        unsafe { command.pre_exec(move || attach_self_to_cgroup(&target)); }
    }
    let mut child = command.spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    (Process(child), line.trim().parse().unwrap(), body_path)
}

pub(crate) fn exchange_body(
    endpoint: &str,
    pg_url: &str,
    library: &Path,
    compiler: &Path,
    digest: &str,
    signer: &SigningKey,
) -> Value {
    exchange_body_for(TENANT, endpoint, pg_url, library, compiler, digest, signer)
}

pub(crate) fn exchange_body_for(
    tenant: &str,
    endpoint: &str,
    pg_url: &str,
    library: &Path,
    compiler: &Path,
    digest: &str,
    signer: &SigningKey,
) -> Value {
    let prefix = format!("lake/parts/v1/tenant={tenant}/");
    let expiry = "2099-01-01T00:00:00Z";
    let credential = |class: &str, permission: &str, prefixes: Vec<String>| {
        json!({
            "credential_class": class, "endpoint": endpoint, "region": "auto", "bucket": "risk-fixture",
            "permission": permission, "prefixes": prefixes, "access_key_id": "local", "secret_access_key": "local",
            "session_token": "local", "expires_at": expiry
        })
    };
    json!({
        "schema_version": 1, "tenant_id": tenant, "role": "detect", "assignment_generation": 4, "writer_epoch": 7,
        "bronze_reader": credential("bronze_reader", "object-read-only", vec![format!("bronze-v2/shard=0/tenant_id={tenant}/")]),
        "notices_url": endpoint,
        "credentials": [
            credential("lake_part_read", "object-read-only", vec![prefix.clone()]),
            credential("lake_part", "object-read-write", ["parts/", "log/checkpoints/", "finding-outbox/receipts/"].map(|s| format!("{prefix}{s}")).to_vec()),
            credential("lake_part_log", "object-read-write", vec![format!("{prefix}log/entries/")])
        ],
        "trusted_keys": [{"key_id":"fixture-owner", "public_key_hex":hex::encode(signer.verifying_key().as_bytes())}],
        "query_engine": {"chdb_library":library, "chdb_sha256":digest, "compiler":compiler,
            "max_query_bytes":67108864, "cache_bytes":67108864, "cache_query_bytes":67108864},
        "owner_sign": {"token":"fixture-owner-token", "audience":"owner", "scope":"lake-parts:sign", "expires_at":expiry},
        "finding_drain": {"tenant_id":tenant, "capability":"finding_drain", "database_url":pg_url, "expires_at":expiry}
    })
}

pub(crate) fn assignment(dir: &Path, control: &str, port: u16, pg_port: u16, signer: &SigningKey) -> Value {
    assignment_for(TENANT, dir, control, port, pg_port, signer)
}

pub(crate) fn assignment_for(tenant: &str, dir: &Path, control: &str, port: u16, pg_port: u16, signer: &SigningKey) -> Value {
    let state = dir.join("state");
    let tmp = dir.join("tmp");
    let store = dir.join("store");
    json!({
        "tenant": tenant, "role":"detect", "cell_id":"risk-cell", "tenant_dir":dir,
        "parts_dir":store, "state_dir":state, "tmp_dir":tmp, "feed_dir":null,
        "memory_cap_bytes":268435456_u64, "cpu_millis":500, "eps":20.0,
        "jail":{"uid":1,"gid":1,"rw_paths":[state,tmp,store],"ro_paths":[dir.join("ca.pem")],
            "system_ro_paths":["/usr","/lib","/lib64","/etc",dir.join("native")],
            "tcp_connect_ports":[port,pg_port],"cgroup_dir":null,"require_landlock":true,
            "max_processes":null,"max_open_files":4096},
        "control_url":control,
        "part_signing":{"url":format!("{control}/owner-sign"),"signer_key_id":"fixture-owner",
            "trusted_keys":[{"key_id":"fixture-owner","public_key_hex":hex::encode(signer.verifying_key().as_bytes())}],
            // lean_part_sign_ca_v1: the fixture CA is the only owner-TLS root.
            "ca_file":dir.join("ca.pem")}
    })
}

pub(crate) fn query_assignment_for(tenant: &str, dir: &Path, control: &str, port: u16, pg_port: u16, signer: &SigningKey) -> Value {
    let mut assignment = assignment_for(tenant, dir, control, port, pg_port, signer);
    let state = dir.join("query-state");
    let tmp = dir.join("query-tmp");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o777)).unwrap();
    assignment["role"] = json!("query");
    assignment["memory_cap_bytes"] = json!(359 * 1_048_576_u64);
    assignment["cpu_millis"] = json!(1000);
    assignment["state_dir"] = json!(state);
    assignment["tmp_dir"] = json!(tmp);
    assignment["jail"]["rw_paths"] = json!([state, tmp]);
    assignment["jail"]["ro_paths"] = json!([dir.join("ca.pem"), dir.join("store")]);
    assignment.as_object_mut().unwrap().remove("part_signing");
    assignment
}

pub(crate) fn ingest_assignment_for(tenant: &str, dir: &Path, control: &str, port: u16, pg_port: u16, signer: &SigningKey) -> Value {
    use std::os::unix::ffi::OsStrExt;
    let mut assignment = assignment_for(tenant, dir, control, port, pg_port, signer);
    let state = dir.join("ingest-state");
    let tmp = dir.join("ingest-tmp");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    for path in [&state, &tmp] {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 1, 1) }, 0,
            "fixture work paths must be owned by the jailed ingest identity");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assignment["role"] = json!("ingest");
    assignment["memory_cap_bytes"] = json!(205 * 1_048_576_u64);
    assignment["state_dir"] = json!(state);
    assignment["tmp_dir"] = json!(tmp);
    assignment["ingest_idle_exit"] = json!(false);
    assignment["jail"]["rw_paths"] = json!([state, tmp, dir.join("store")]);
    assignment["jail"]["ro_paths"] = json!([dir.join("ca.pem")]);
    assignment
}

pub(crate) fn make_tls(dir: &Path) -> PathBuf {
    let cert = dir.join("ca.pem");
    let ca_key = dir.join("ca.key");
    let leaf_key = dir.join("leaf.key");
    let csr = dir.join("leaf.csr");
    let leaf_cert = dir.join("leaf.pem");
    let ext = dir.join("leaf.ext");
    std::fs::write(&ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
    checked(Command::new("openssl").args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout"])
        .arg(&ca_key).arg("-out").arg(&cert).args(["-subj", "/CN=fixture-ca", "-addext", "basicConstraints=critical,CA:TRUE"]));
    checked(Command::new("openssl").args(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&leaf_key).arg("-out").arg(&csr).args(["-subj", "/CN=localhost"]));
    checked(Command::new("openssl").args(["x509", "-req", "-in"]).arg(&csr)
        .arg("-CA").arg(&cert).arg("-CAkey").arg(&ca_key).arg("-CAcreateserial")
        .arg("-out").arg(&leaf_cert).args(["-days", "1", "-extfile"]).arg(&ext));
    cert
}

pub(crate) fn spawn_child(dir: &Path, cert: &Path) -> (Process, std::os::fd::OwnedFd) {
    spawn_child_role(dir, cert, "detect")
}

pub(crate) fn spawn_query_child(dir: &Path, cert: &Path) -> (Process, std::os::fd::OwnedFd) {
    spawn_child_role(dir, cert, "query")
}

pub(crate) fn spawn_ingest_child(dir: &Path, cert: &Path) -> (Process, std::os::fd::OwnedFd) {
    spawn_child_role(dir, cert, "ingest")
}

fn spawn_child_role(dir: &Path, cert: &Path, role: &str) -> (Process, std::os::fd::OwnedFd) {
    let (parent, child) = fdpass::seqpacket_pair().unwrap();
    let fd = child.as_raw_fd();
    let binary = if role == "ingest" {
        PathBuf::from(std::env::var("NANO_RISK_TEST_INGEST_BIN").expect("release ingest binary for measured role"))
    } else { detect_binary() };
    let mut command = Command::new(binary);
    let stderr = std::fs::File::create(dir.join(format!("{role}.stderr"))).unwrap();
    let stdout = std::fs::File::create(dir.join(format!("{role}.stdout"))).unwrap();
    stderr.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
    stdout.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
    command
        .arg("--cell-control-fd")
        .arg("3")
        .env("SSL_CERT_FILE", cert)
        .stderr(Stdio::from(stderr))
        .stdout(Stdio::from(stdout))
        .current_dir(dir);
    let cgroup_target = std::fs::read_to_string(dir.join("tenant-cgroup"))
        .ok().map(|root| std::ffi::CString::new(
            PathBuf::from(root.trim()).join(role).join("cgroup.procs")
                .as_os_str().as_bytes()).unwrap());
    // SAFETY: pre_exec only duplicates the already-open socket; dup2 clears CLOEXEC on fd3.
    unsafe {
        command.pre_exec(move || {
            if let Some(target) = &cgroup_target {
                attach_self_to_cgroup(target)?;
            }
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child_process = command.spawn().unwrap();
    drop(child);
    (Process(child_process), parent)
}

pub(crate) fn handshake(control: &std::os::fd::OwnedFd, assignment: Value) {
    let (hello, _) = fdpass::recv_json::<ToSupervisor>(control.as_fd())
        .unwrap()
        .unwrap();
    let ToSupervisor::Hello { pid, protocol_version } = hello else {
        panic!("child did not announce its process: {hello:?}")
    };
    assert_eq!(protocol_version, PROTOCOL_VERSION);
    if let Some(root) = std::env::var_os("NANO_RISK_ROLE_CGROUP_ROOT") {
        let tenant = assignment["tenant"].as_str().expect("assigned tenant");
        let role = assignment["role"].as_str().expect("assigned role");
        assert!(matches!(role, "detect" | "query" | "ingest"));
        let target = Path::new(&root).join(tenant).join(role);
        std::fs::write(target.join("cgroup.procs"), pid.to_string())
            .expect("move real child into delegated role cgroup");
        assert_eq!(std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap()
            .trim().rsplit('/').next(), Some(role));
    }
    fdpass::send_json(
        control.as_fd(),
        &ToChild::Assign {
            protocol_version: PROTOCOL_VERSION,
            assignment: Box::new(serde_json::from_value(assignment).unwrap()),
        },
        &[],
    )
    .unwrap();
    let (jailed, _) = fdpass::recv_json::<ToSupervisor>(control.as_fd())
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            jailed,
            ToSupervisor::Jailed {
                uid: 1,
                gid: 1,
                seccomp: true,
                ..
            }
        ),
        "{jailed:?}"
    );
    let secret = fdpass::secret_memfd(TOKEN).unwrap();
    fdpass::send_json(control.as_fd(), &ToChild::Secrets, &[secret.as_fd()]).unwrap();
    let (ready, _) = fdpass::recv_json::<ToSupervisor>(control.as_fd())
        .unwrap()
        .unwrap();
    assert!(matches!(ready, ToSupervisor::Ready));
}

/// The composed fixture models the cell supervisor's role-checked fd pass.
/// Both child processes remain jailed: neither creates an AF_UNIX socket.
pub(crate) fn bridge_finding_appends(detect: &std::os::fd::OwnedFd, ingest: &std::os::fd::OwnedFd) {
    let detect = detect.as_fd().try_clone_to_owned().unwrap();
    let ingest = ingest.as_fd().try_clone_to_owned().unwrap();
    std::thread::spawn(move || loop {
        match fdpass::recv_json::<ToSupervisor>(detect.as_fd()) {
            Ok(Some((ToSupervisor::ConnectIngest { request_id }, fds))) if fds.is_empty() => {
                let (detect_end, ingest_end) = fdpass::stream_pair().unwrap();
                if fdpass::send_json(ingest.as_fd(), &ToChild::FindingAppend { request_id }, &[ingest_end.as_fd()]).is_err() {
                    break;
                }
                if fdpass::send_json(detect.as_fd(), &ToChild::PeerRpc { request_id }, &[detect_end.as_fd()]).is_err() {
                    break;
                }
            }
            Ok(Some((ToSupervisor::Heartbeat(_), _))) => {}
            Ok(Some((ToSupervisor::Fatal { .. }, _))) | Ok(None) | Err(_) => break,
            Ok(Some((_, _))) => {}
        }
    });
}

pub(crate) async fn rpc(
    control: &std::os::fd::OwnedFd,
    path: &str,
    method: Method,
    body: Option<Value>,
) -> (u16, Value) {
    let (host, peer) = fdpass::stream_pair().unwrap();
    fdpass::send_json(
        control.as_fd(),
        &ToChild::Rpc { request_id: 1 },
        &[peer.as_fd()],
    )
    .unwrap();
    drop(peer);
    let socket = std::os::unix::net::UnixStream::from(host);
    socket.set_nonblocking(true).unwrap();
    let socket = tokio::net::UnixStream::from_std(socket).unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "cell")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            body.map(|v| v.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        Value::String(
            String::from_utf8_lossy(&bytes)
                .replace("fixture-bootstrap-token", "[redacted]")
                .replace("fixture-owner-token", "[redacted]"),
        )
    });
    (status, value)
}

fn refused_bootstrap(
    dir: &Path,
    store: &Path,
    cert: &Path,
    pg_port: u16,
    signer: &SigningKey,
    mut response: Value,
    reason: &str,
) {
    let (server, port, body_path) = https_stub(dir, &response, store);
    let endpoint = format!("https://localhost:{port}");
    for credential in response["credentials"].as_array_mut().unwrap() {
        credential["endpoint"] = json!(endpoint);
    }
    std::fs::write(body_path, serde_json::to_vec(&response).unwrap()).unwrap();
    let (child, control) = spawn_child(dir, cert);
    handshake(&control, assignment(dir, &endpoint, port, pg_port, signer));
    let (event, _) = fdpass::recv_json::<ToSupervisor>(control.as_fd())
        .unwrap()
        .expect("bootstrap refusal");
    let ToSupervisor::Fatal { error } = event else {
        panic!("bad bootstrap unexpectedly served: {event:?}")
    };
    assert!(
        error.contains(reason),
        "unexpected bootstrap refusal: {error}"
    );
    drop(control);
    drop(child);
    drop(server);
}

#[test]
fn real_detect_child_serves_owner_signed_source() {
    if std::env::var_os("NANO_RISK_TEST_PG").is_none() {
        eprintln!("SKIPPED: set NANO_RISK_TEST_PG to a disposable PostgreSQL 18 database");
        return;
    }
    if std::env::var_os("NANO_RISK9C_USERNS").is_none() {
        let exe = std::env::current_exe().unwrap();
        let status = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--map-users=1:100000:65535",
                "--map-groups=1:100000:65535",
                "--",
            ])
            .arg(exe)
            .args([
                "real_detect_child_serves_owner_signed_source",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NANO_RISK9C_USERNS", "1")
            .status()
            .unwrap();
        assert!(status.success(), "user namespace fixture failed: {status}");
        return;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let admin_url =
        std::env::var("NANO_RISK_TEST_PG").expect("disposable PG18 NANO_RISK_TEST_PG required");
    let compiler_source =
        std::env::var("NANO_RISK_TEST_COMPILER").expect("built lake_query_compile required");
    let library_source = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("native chDB required");
    let expected_digest =
        std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("native SHA-256 required");
    assert_eq!(
        nanosiem_lake_worker::native::file_sha256(Path::new(&library_source)).unwrap(),
        expected_digest
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    for name in ["store", "state", "tmp", "work", "native"] {
        std::fs::create_dir(dir.path().join(name)).unwrap();
        std::fs::set_permissions(
            dir.path().join(name),
            std::os::unix::fs::PermissionsExt::from_mode(0o777),
        )
        .unwrap();
    }
    let library = dir.path().join("native/libchdb.so");
    let compiler = dir.path().join("native/lake_query_compile");
    checked(
        Command::new("cp")
            .arg("--reflink=auto")
            .arg(&library_source)
            .arg(&library),
    );
    checked(
        Command::new("cp")
            .arg("--reflink=auto")
            .arg(&compiler_source)
            .arg(&compiler),
    );
    assert_eq!(
        nanosiem_lake_worker::native::file_sha256(&library).unwrap(),
        expected_digest
    );
    release_fixture_library_cache(&library);
    let compiler_digest = nanosiem_lake_worker::native::file_sha256(&compiler).unwrap();
    let signer_key = SigningKey::from_bytes(&[37; 32]);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(setup_pg(&admin_url));
    let cert = make_tls(dir.path());
    let drain_url = admin_url.replace("postgres@", "risk_drain@");
    // The stub binds an ephemeral port; fill the body endpoint before exchange.
    let mut base = exchange_body(
        "https://localhost:0",
        &drain_url,
        &library,
        &compiler,
        &expected_digest,
        &signer_key,
    );
    let (server, actual_port, body_path) = https_stub(dir.path(), &base, &dir.path().join("store"));
    let endpoint = format!("https://localhost:{actual_port}");
    base = exchange_body(
        &endpoint,
        &drain_url,
        &library,
        &compiler,
        &expected_digest,
        &signer_key,
    );
    std::fs::write(body_path, serde_json::to_vec(&base).unwrap()).unwrap();
    std::env::set_var("SSL_CERT_FILE", &cert);
    let trusted = TenantKeySet::new([("fixture-owner".into(), signer_key.verifying_key())]);
    let owner = HttpPartSigner::new(
        &format!("{endpoint}/owner-sign"),
        "fixture-owner-token",
        "fixture-owner",
        trusted.clone(),
        Some(cert.as_path()),
    )
    .unwrap();
    let time_us = runtime.block_on(signed_source(
        &dir.path().join("store"),
        &dir.path().join("work"),
        &owner,
        &trusted,
    ));
    let assignment = assignment(
        dir.path(),
        &endpoint,
        actual_port,
        pg_port(&admin_url),
        &signer_key,
    );
    let (child, control) = spawn_child(dir.path(), &cert);
    assert!(child.0.id() > 0);
    handshake(&control, assignment);
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/exe", child.0.id())).unwrap(),
        detect_binary(),
        "the detect service must be the built lake_part_query binary"
    );
    let (first, _) = fdpass::recv_json::<ToSupervisor>(control.as_fd())
        .unwrap()
        .unwrap_or_else(|| {
            let message = std::fs::read_to_string(dir.path().join("detect.stderr"))
                .unwrap_or_default()
                .replace("fixture-bootstrap-token", "[redacted]")
                .replace("fixture-owner-token", "[redacted]");
            panic!("child exited after Ready: {message}")
        });
    assert!(
        matches!(first, ToSupervisor::Heartbeat(_)),
        "child failed after bootstrap: {first:?}"
    );
    let query_assignment = query_assignment_for(TENANT, dir.path(), &endpoint, actual_port,
        pg_port(&admin_url), &signer_key);
    let (query_child, query_control) = spawn_query_child(dir.path(), &cert);
    handshake(&query_control, query_assignment);
    let (query_first, _) = fdpass::recv_json::<ToSupervisor>(query_control.as_fd())
        .unwrap().expect("query startup heartbeat");
    assert!(matches!(query_first, ToSupervisor::Heartbeat(_)), "query child failed after bootstrap: {query_first:?}: {}",
        std::fs::read_to_string(dir.path().join("query.stderr")).unwrap_or_default()
            .replace("fixture-bootstrap-token", "[redacted]").replace("fixture-owner-token", "[redacted]")
            .lines().rev().take(20).collect::<Vec<_>>().join("\n"));
    // An old router still dispatches detect RPCs to the Detect child. The
    // new drain-only child closes that stream instead of executing a read
    // with the wrong role or silently acknowledging a scheduled detection.
    let (legacy_stream, legacy_peer) = fdpass::stream_pair().unwrap();
    fdpass::send_json(control.as_fd(), &ToChild::Rpc { request_id: 77 }, &[legacy_peer.as_fd()]).unwrap();
    drop(legacy_peer);
    let mut legacy_stream = std::os::unix::net::UnixStream::from(legacy_stream);
    legacy_stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let mut legacy_byte = [0_u8; 1];
    assert_eq!(std::io::Read::read(&mut legacy_stream, &mut legacy_byte).unwrap(), 0,
        "mixed-version old-router detect RPC must fail closed");
    assert!(!std::fs::read_to_string(format!("/proc/{}/maps", child.0.id())).unwrap()
        .contains("libchdb.so"), "detect drain loaded the native engine");
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            let (code, value) = rpc(&query_control, "/v1/status", Method::GET, None).await;
            if code == 200 { break value; }
            assert!(Instant::now() < deadline, "detect status never became ready: {value}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        assert_eq!(status["tenant_id"], TENANT);
        assert_eq!(status["compiler_sha256"], compiler_digest);
        assert_eq!(status["native_artifact_sha256"], expected_digest);
        assert_eq!(status["log_head"]["seq"], 1);
        let (plan_code, plan) = rpc(&query_control, "/v1/detections/plan", Method::POST,
            Some(json!({"rule_id":"fixture-rule", "window_start_us":time_us-1_000_000,
                "window_end_us":time_us+1_000_000}))).await;
        assert_eq!(plan_code, 200, "{plan}");
        assert_eq!(plan["run"], true);
        let (query_code, result) = rpc(&query_control, "/v1/query", Method::POST, Some(json!({
            "route":"broad_npl", "request_id":"real-detect-source", "tenant_id":TENANT,
            "dataset":"logs", "query":"* | table message", "start":chrono::DateTime::from_timestamp_micros(time_us-1_000_000).unwrap().to_rfc3339(),
            "end":chrono::DateTime::from_timestamp_micros(time_us+1_000_000).unwrap().to_rfc3339(),
            "limit":10,"table_view":false
        }))).await;
        assert_eq!(query_code, 200, "{result}");
        assert_eq!(result["result"]["result_rows"], 1, "{result}");
        assert_eq!(result["result"]["rows"][0]["message"], "detect-real-source-row");
        let (foreign_code, _) = rpc(&query_control, "/v1/query", Method::POST, Some(json!({
            "route":"broad_npl", "request_id":"foreign", "tenant_id":FOREIGN,
            "dataset":"logs", "query":"*", "start":chrono::DateTime::from_timestamp_micros(time_us-1_000_000).unwrap().to_rfc3339(),
            "end":chrono::DateTime::from_timestamp_micros(time_us+1_000_000).unwrap().to_rfc3339(),
            "limit":10,"table_view":false
        }))).await;
        assert_ne!(foreign_code, 200);
    });
    let child_log = std::fs::read_to_string(dir.path().join("detect.stdout")).unwrap();
    assert!(
        child_log.contains("\"generation\":4") && child_log.contains("\"epoch\":7"),
        "detect drain must accept the shared assignment generation and writer epoch"
    );
    drop(control);
    drop(child);
    // NAN-3047: a detect child assigned `detect_runs_rules` serves the rule
    // reads, the gate and prevalence itself (its own chDB), with the finding
    // drain beside it, on the same single detect exchange.
    let mut rules_assignment = assignment_for(TENANT, dir.path(), &endpoint, actual_port, pg_port(&admin_url), &signer_key);
    rules_assignment["detect_runs_rules"] = json!(true);
    rules_assignment["memory_cap_bytes"] = json!(2_u64 << 30);
    rules_assignment["cpu_millis"] = json!(1000);
    let (rules_child, rules_control) = spawn_child(dir.path(), &cert);
    handshake(&rules_control, rules_assignment);
    let (rules_first, _) = fdpass::recv_json::<ToSupervisor>(rules_control.as_fd()).unwrap().expect("rules detect heartbeat");
    assert!(matches!(rules_first, ToSupervisor::Heartbeat(_)), "rules detect failed after bootstrap: {rules_first:?}: {}",
        std::fs::read_to_string(dir.path().join("detect.stderr")).unwrap_or_default()
            .replace("fixture-bootstrap-token", "[redacted]").replace("fixture-owner-token", "[redacted]"));
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            let (code, value) = rpc(&rules_control, "/v1/status", Method::GET, None).await;
            if code == 200 { break value; }
            assert!(Instant::now() < deadline, "rules detect status never became ready: {value}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        assert_eq!(status["tenant_id"], TENANT);
        let (plan_code, plan) = rpc(&rules_control, "/v1/detections/plan", Method::POST,
            Some(json!({"rule_id":"fixture-rule-detect", "window_start_us":time_us-1_000_000,
                "window_end_us":time_us+1_000_000}))).await;
        assert_eq!((plan_code, &plan["run"]), (200, &json!(true)), "{plan}");
        let (query_code, result) = rpc(&rules_control, "/v1/query", Method::POST, Some(json!({
            "route":"broad_npl", "request_id":"real-detect-rules", "tenant_id":TENANT,
            "dataset":"logs", "query":"* | table message", "start":chrono::DateTime::from_timestamp_micros(time_us-1_000_000).unwrap().to_rfc3339(),
            "end":chrono::DateTime::from_timestamp_micros(time_us+1_000_000).unwrap().to_rfc3339(),
            "limit":10,"table_view":false
        }))).await;
        assert_eq!(query_code, 200, "{result}");
        assert_eq!(result["result"]["rows"][0]["message"], "detect-real-source-row");
    });
    assert!(std::fs::read_to_string(format!("/proc/{}/maps", rules_child.0.id())).unwrap().contains("libchdb.so"),
        "a rules-mode detect runs its own engine");
    let rules_log = std::fs::read_to_string(dir.path().join("detect.stdout")).unwrap();
    assert!(rules_log.contains("detect runs rule searches in its own engine")
        && rules_log.contains("\"generation\":4"), "rules detect keeps its finding drain: {rules_log}");
    drop(rules_control);
    drop(rules_child);
    drop(query_control);
    drop(query_child);
    drop(server);
    let mut foreign = base.clone();
    foreign["tenant_id"] = json!(FOREIGN);
    refused_bootstrap(
        dir.path(),
        &dir.path().join("store"),
        &cert,
        pg_port(&admin_url),
        &signer_key,
        foreign,
        "binding differs",
    );
    let mut foreign_epoch = base.clone();
    foreign_epoch["writer_epoch"] = json!(0);
    refused_bootstrap(
        dir.path(),
        &dir.path().join("store"),
        &cert,
        pg_port(&admin_url),
        &signer_key,
        foreign_epoch,
        "lacks an assignment generation or writer epoch",
    );
    let mut missing_epoch = base;
    missing_epoch
        .as_object_mut()
        .unwrap()
        .remove("writer_epoch");
    refused_bootstrap(
        dir.path(),
        &dir.path().join("store"),
        &cert,
        pg_port(&admin_url),
        &signer_key,
        missing_epoch,
        "missing field",
    );
}
